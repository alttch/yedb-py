#!/usr/bin/env pytest

import pytest
import os
import signal
import time
import subprocess

from pathlib import Path
from yedb import YEDB, FMTS
from yedb.server import PID_FILE

from types import SimpleNamespace

_d = SimpleNamespace(p=None)

DB_PATH = '/tmp/yedb-test'

SERVER_DB_PATH = '/tmp/yedb-server-test'


def clear():
    os.system(f'rm -rf {DB_PATH}')


def kill_server():
    if _d.p:
        _d.p.kill()
    try:
        pid = int(Path(PID_FILE).read_text())
        os.kill(pid, signal.SIGKILL)
        os.unlink(PID_FILE)
    except FileNotFoundError:
        pass
    except ProcessLookupError:
        pass


class Server:

    def __init__(self, is_server):
        self.is_server = is_server

    def __enter__(self):
        if self.is_server:
            uri = 'http://localhost:8879'
            with YEDB(uri) as db:
                db.key_delete_recursive(key='/')
            return uri
        else:
            return DB_PATH

    def __exit__(self, exc_type, exc_val, exc_tb):
        pass


@pytest.fixture(scope='module', autouse=True)
def manage():
    _d.p = subprocess.Popen(
        f'python3 -m yedb.server {SERVER_DB_PATH} '
        '-B http://127.0.0.1:8879 --default-fmt msgpack',
        shell=True)
    time.sleep(0.5)
    yield
    kill_server()
    clear()
    os.system(f'rm -rf {SERVER_DB_PATH}')


@pytest.mark.parametrize('fmt', FMTS)
@pytest.mark.parametrize('cfmt', FMTS)
@pytest.mark.parametrize('checksums', [False, True])
def test_create_and_convert(fmt, cfmt, checksums):
    clear()
    db = YEDB(DB_PATH, default_fmt=fmt, default_checksums=checksums)
    db.open()
    db.close()
    db.open()
    try:
        info = db.info()
        assert info['fmt'] == fmt
        assert info['checksums'] == checksums
        db.key_set('key1', 'test')
        db.key_set('keys/k1', 123)
        db.key_set('keys/k2', dict(a=2, b=3))
    finally:
        db.close()
    list(db.convert_fmt(cfmt, checksums=not checksums))
    db.open()
    try:
        assert list(db.check()) == []
        info = db.info()
        assert info['fmt'] == cfmt
        assert info['checksums'] == (not checksums)
        assert db.key_get('key1') == 'test'
        assert db.key_get('keys/k1') == 123
        assert db.key_get('keys/k2') == dict(a=2, b=3)
    finally:
        db.close()


@pytest.mark.parametrize('fmt', FMTS + ['server'])
@pytest.mark.parametrize('key', ['', 'key1', 'keys/key1', 'keys/group/key1'])
@pytest.mark.parametrize(
    'value',
    ['test', 123, 1234.567, ['1', '2', '3'],
     dict(a=2, b=3), b'\x01\x02\x03'])
def test_basic(fmt, key, value):
    # rapidjson breaks binary data, native json raises exception
    if fmt == 'json' and isinstance(value, bytes):
        return
    clear()
    with Server(fmt == 'server') as dbpath:
        with YEDB(dbpath, default_fmt=fmt) as db:
            if key:
                db.key_set(key=key, value=value)
            else:
                with pytest.raises(Exception):
                    db.key_set(key=key, value=value)
                return
            assert db.key_get(key=key) == value
            assert db.key_exists(key=key) is True
            ki = db.key_explain(key=key)
            db.key_delete(key=key)
            with pytest.raises((KeyError, RuntimeError)):
                db.key_get(key='key')
            with pytest.raises((KeyError, RuntimeError)):
                db.key_explain(key='key')
            assert db.key_exists(key=key) is False
            db.key_delete(key=key)
            db.key_set(key=key, value=value)
            assert db.key_get(key=key) == value
            key2 = 'renamed/' + key
            db.key_rename(key=key, dst_key=key2)
            assert db.key_get(key=key2) == value
            db.key_delete(key=key2)
            db.key_set(key=key, value=value)
            key2 = 'copied/' + key
            db.key_copy(key=key, dst_key=key2)
            assert db.key_get(key=key) == db.key_get(key=key2)
            db.key_delete(key=key)
            db.key_delete(key=key2)


@pytest.mark.parametrize('server', [False, True])
def test_check_purge(server):
    clear()
    with Server(server) as dbpath:
        with YEDB(dbpath, default_fmt='msgpack') as db:
            db.key_set(key='key1', value='123')
            db.key_set(key='broken/key2', value='123')
            key_file = Path(
                f'{SERVER_DB_PATH if server else DB_PATH}/keys/broken/key2.mpc')
            assert key_file.is_file() is True
            key_file.write_text('')
            assert list(db.check()) == ['broken/key2']
            assert list(db.purge()) == ['broken/key2']
            assert list(db.check()) == []


@pytest.mark.parametrize('server', [False, True])
def test_list_get_subkeys(server):
    clear()
    with Server(server) as dbpath:
        with YEDB(dbpath) as db:
            with db.session() as session:
                session.key_set(key='key1', value='0')
                session.key_set(key='d/k1', value='1')
                session.key_set(key='d/k2', value='2')
                session.key_set(key='d/k3', value='3')
                assert sorted(list(session.key_list(key='/'))) == [
                    'd/k1', 'd/k2', 'd/k3', 'key1'
                ]
                assert sorted(list(
                    session.key_list())) == ['d/k1', 'd/k2', 'd/k3', 'key1']
                assert sorted(list(
                    session.key_list(key='/d'))) == ['d/k1', 'd/k2', 'd/k3']
                assert sorted(list(
                    session.key_list(key='d'))) == ['d/k1', 'd/k2', 'd/k3']
                assert sorted([list(x) for x in session.key_get_recursive()
                              ]) == [['d/k1', '1'], ['d/k2', '2'],
                                     ['d/k3', '3'], ['key1', '0']]
                assert sorted([
                    list(x) for x in (session.key_get_recursive(key='d'))
                ]) == [['d/k1', '1'], ['d/k2', '2'], ['d/k3', '3']]


@pytest.mark.parametrize('server', [False, True])
def test_key_as_dict(server):
    clear()
    with Server(server) as dbpath:
        with YEDB(dbpath) as db:
            with db.key_as_dict('keys/d1') as key:
                key.set('data', 123)
                key.set('data2', 'test')
            with db.key_as_dict('keys/d1') as key:
                assert key.get('data') == 123
                assert key.get('data2') == 'test'
                key.delete('data')
            with db.key_as_dict('keys/d1') as key:
                with pytest.raises(KeyError):
                    key.get('data')
                assert key.get('data2') == 'test'


@pytest.mark.parametrize('server', [False, True])
def test_key_list(server):
    clear()
    with Server(server) as dbpath:
        with YEDB(dbpath) as db:
            with db.key_as_list('keys/l1') as key:
                key.append(123)
                key.append('test')
            with db.key_as_list('keys/l1') as key:
                assert key.data == [123, 'test']
                key.remove(123)
            with db.key_as_list('keys/l1') as key:
                assert key.data == ['test']
                key.data.clear()
                key.set_modified()
            with db.key_as_list('keys/l1') as key:
                assert key.data == []
