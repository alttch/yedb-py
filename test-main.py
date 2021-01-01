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
            uri = 'http://localhost:8870'
            with YEDB(uri) as db:
                db.delete(key='/', recursive=True)
            return uri
        else:
            return DB_PATH

    def __exit__(self, exc_type, exc_val, exc_tb):
        pass


@pytest.fixture(scope='module', autouse=True)
def manage():
    _d.p = subprocess.Popen(
        f'python3 -m yedb.server {SERVER_DB_PATH} --default-fmt msgpack',
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
        db.set('key1', 'test')
        db.set('keys/k1', 123)
        db.set('keys/k2', dict(a=2, b=3))
    finally:
        db.close()
    list(db.convert_fmt(cfmt, checksums=not checksums))
    db.open()
    try:
        assert list(db.check()) == []
        info = db.info()
        assert info['fmt'] == cfmt
        assert info['checksums'] == (not checksums)
        assert db.get('key1') == 'test'
        assert db.get('keys/k1') == 123
        assert db.get('keys/k2') == dict(a=2, b=3)
    finally:
        db.close()


@pytest.mark.parametrize('fmt', FMTS + ['server'])
@pytest.mark.parametrize('key', ['', 'key1', 'keys/key1', 'keys/group/key1'])
@pytest.mark.parametrize(
    'value',
    ['test', 123, 1234.567, ['1', '2', '3'],
     dict(a=2, b=3), b'\x01\x02\x03'])
@pytest.mark.parametrize('flush', [False, True])
@pytest.mark.parametrize('stime', [None, time.time_ns()])
def test_basic(fmt, key, value, flush, stime):
    # rapidjson breaks binary data, native json raises exception
    if fmt == 'json' and isinstance(value, bytes):
        return
    clear()
    with Server(fmt == 'server') as dbpath:
        with YEDB(dbpath, default_fmt=fmt) as db:
            if key:
                db.set(key=key, value=value, flush=flush, stime=stime)
            else:
                with pytest.raises(Exception):
                    db.set(key=key, value=value, flush=flush, stime=stime)
                return
            assert db.get(key=key) == value
            assert db.key_exists(key=key) is True
            ki = db.explain(key=key)
            if stime:
                assert ki['stime'] == stime
            db.delete(key=key)
            with pytest.raises((KeyError, RuntimeError)):
                db.get(key='key')
            with pytest.raises((KeyError, RuntimeError)):
                db.explain(key='key')
            assert db.key_exists(key=key) is False
            db.delete(key=key)
            db.set(key=key, value=value, flush=flush, stime=stime)
            assert db.get(key=key) == value
            key2 = 'renamed/' + key
            db.rename(key=key, dst_key=key2)
            assert db.get(key=key2) == value
            db.delete(key=key2)
            db.set(key=key, value=value, flush=flush, stime=stime)
            key2 = 'copied/' + key
            db.copy(key=key, dst_key=key2)
            assert db.get(key=key) == db.get(key=key2)
            db.delete(key=key)
            db.delete(key=key2)


@pytest.mark.parametrize('server', [False, True])
def test_check_purge(server):
    clear()
    with Server(server) as dbpath:
        with YEDB(dbpath, default_fmt='msgpack') as db:
            db.set(key='key1', value='123')
            db.set(key='broken/key2', value='123')
            key_file = Path(
                f'{SERVER_DB_PATH if server else DB_PATH}/broken/key2.mpc')
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
            db.set(key='key1', value='0')
            db.set(key='d/k1', value='1')
            db.set(key='d/k2', value='2')
            db.set(key='d/k3', value='3')
            assert sorted(list(
                db.list_subkeys(key='/'))) == ['d/k1', 'd/k2', 'd/k3', 'key1']
            assert sorted(list(
                db.list_subkeys())) == ['d/k1', 'd/k2', 'd/k3', 'key1']
            assert sorted(list(
                db.list_subkeys(key='/d'))) == ['d/k1', 'd/k2', 'd/k3']
            assert sorted(list(
                db.list_subkeys(key='d'))) == ['d/k1', 'd/k2', 'd/k3']
            assert sorted([list(x) for x in db.get_subkeys()
                          ]) == [['d/k1', '1'], ['d/k2', '2'], ['d/k3', '3'],
                                 ['key1', '0']]
            assert sorted([list(x) for x in (db.get_subkeys(key='d'))
                          ]) == [['d/k1', '1'], ['d/k2', '2'], ['d/k3', '3']]


def test_key_dict():
    clear()
    with YEDB(DB_PATH) as db:
        with db.key_dict('keys/d1') as key:
            key.set('data', 123)
            key.set('data2', 'test')
        with db.key_dict('keys/d1') as key:
            assert key.get('data') == 123
            assert key.get('data2') == 'test'
            key.delete('data')
        with db.key_dict('keys/d1') as key:
            with pytest.raises(KeyError):
                key.get('data')
            assert key.get('data2') == 'test'


def test_key_list():
    clear()
    with YEDB(DB_PATH) as db:
        with db.key_list('keys/l1') as key:
            key.append(123)
            key.append('test')
        with db.key_list('keys/l1') as key:
            assert key.data == [123, 'test']
            key.remove(123)
        with db.key_list('keys/l1') as key:
            assert key.data == ['test']
            key.data.clear()
            key.set_modified()
        with db.key_list('keys/l1') as key:
            assert key.data == []
