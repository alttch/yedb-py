__version__ = '0.0.20'

DB_VERSION = 1

DEFAULT_FMT = 'json'

DEFAULT_HTTP_TIMEOUT = 5

FMTS = ['json', 'yaml', 'msgpack', 'cbor', 'pickle']

import threading

g = threading.local()

from pathlib import Path
from functools import partial

import os

import logging

logger = logging.getLogger('yedb')

debug = False

import time

try:
    time_ns = time.time_ns
except:
    time_ns = lambda: int(time.time() * 1000000000)


class ChecksumError(Exception):

    def __str__(self):
        return 'Checksum error'


def _format_debug_value(v):
    dv = str(v)
    if len(dv) > 79:
        dv = dv[:76] + '...'
    return dv


class YEDB():
    """
    File-based database

    The object is thread-safe
    """

    def _remote_call(self, method, **kwargs):
        import uuid
        req = {
            'jsonrpc': '2.0',
            'id': str(uuid.uuid4()),
            'method': method,
            'params': kwargs
        }
        try:
            import msgpack
            use_msgpack = True
            data = msgpack.dumps(req)
            headers = {'Content-Type': 'application/x-msgpack'}
        except ModuleNotFoundError:
            try:
                import rapidjson as json
            except:
                import json
            use_msgpack = False
            data = json.dumps(req)
            headers = {'Content-Type': 'application/json'}
        if debug:
            logger.debug(f'JRPC ({"msgpack" if use_msgpack else "json"}) '
                         f'{self.db} method={method} auth={self.http_auth}')
        # according to tests, session is 3x slower than singles
        # try:
        # post = g.session.post
        # except AttributeError:
        # import requests
        # session = requests.Session()
        # g.session = session
        # post = session.post
        from requests import post
        r = post(self.db,
                 data=data,
                 headers=headers,
                 timeout=self.http_timeout,
                 auth=self.http_auth)
        if not r.ok:
            raise RuntimeError(f'http response code {r.status_code}')
        if use_msgpack:
            data = msgpack.loads(r.content, raw=False)
        else:
            data = json.loads(r.text)
        try:
            raise RuntimeError(data['error']['message'])
        except KeyError:
            return data['result']

    def _empty(self, *args, **kwargs):
        pass

    def _not_implemented(self, *args, **kwargs):
        raise RuntimeError('not implemented in remote mode')

    def _test_remote(self):
        result = self._remote_call('test')
        if result.get('name') != 'yedb':
            raise RuntimeError('unsupported RPC server')
        return result

    def __init__(
        self,
        dbpath,
        default_fmt=DEFAULT_FMT,
        default_checksums=True,
        **kwargs,
    ):
        """
        Create / open database

        Data formats supported:

        json: JSON (uses rapidjson module if present), default
        yaml, yml: YAML (requires "pyyaml" module)
        msgpack: MessagePack (requires "msgpack-python" module)
        cbor: CBOR (requires "cbor" module)
        pickle: Python's native pickle

        Can be used either directly or via with statement:

        with yedb.YEDB('/path/to/db1') as db:
            # do something

        Key parts are split with "/" symbols

        If dbpath is specified as HTTP/HTTPS URI, the object transforms itself
        into JSON RPC client (methods, not listed at yedb.server.METHODS become
        unimplemented)

        Args:
            dbpath: database directory
            default_fmt: default data format
            default_checksums: use SHA256 checksums by default
            http_timeout: server timeout (for client/server mode)
            http_username: http username
            http_password: http password
            http_auth: auth type (basic or digest)
        """
        path = str(dbpath)
        self.auto_repair = kwargs.get('auto_repair')
        if debug:
            logger.debug('initializing db')
            logger.debug(f'path: {path}')
            logger.debug(f'options: {kwargs}')
        if path.startswith('http://') or path.startswith('https://'):
            self.db = path
            self.http_timeout = kwargs.get('http_timeout', DEFAULT_HTTP_TIMEOUT)
            username = kwargs.get('http_username')
            if username:
                password = kwargs.get('http_password', '')
                auth_type = kwargs.get('http_auth', 'basic')
                if auth_type == 'basic':
                    from requests.auth import HTTPBasicAuth as Auth
                elif auth_type == 'digest':
                    from requests.auth import HTTPDigestAuth as Auth
                else:
                    raise ValueError(f'Unsupported auth type: {auth_type}')
                self.http_auth = Auth(username, password)
            else:
                self.http_auth = None
            from yedb.server import METHODS
            for f in dir(self):
                fn = getattr(self, f)
                if fn.__class__.__name__ == 'method':
                    if f == 'open':
                        setattr(self, f, self._test_remote)
                    elif f == 'close':
                        setattr(self, f, self._empty)
                    elif not f.startswith('_'):
                        if f in METHODS:
                            setattr(self, f, partial(self._remote_call, f))
                        else:
                            setattr(self, f, self._not_implemented)
        else:
            self.db = Path(dbpath).absolute()
            self.default_fmt = default_fmt if default_fmt else DEFAULT_FMT
            self.default_checksums = default_checksums
            self._dbpath_len = len(self.db.absolute().as_posix()) + 1
            self.lock = threading.RLock()
            self._key_locks = {}
            self._opened = False
            self._flock = None
            self._flock_fh = None
            self.lock_file = (self.db / 'db.lock').absolute()
            self.meta_file = (self.db / '.yedb').absolute()
            self.safe_write = True
            self.auto_flush = True
            self.lock_ex = True
            self.force_native_json = False
            self._parse_options(kwargs)

    def _parse_options(self, options):
        for o in ['safe_write', 'auto_flush', 'lock_ex']:
            try:
                val = options[o]
                if val is not None:
                    setattr(self, o, options[o])
            except KeyError:
                pass

    def _init_db(self):
        self.dbinfo = {
            'lock_ex': self.lock_ex,
            'safe_write': self.safe_write,
            'auto_flush': self.auto_flush,
            'path': Path(self.db),
        }
        dump_kwargs = None
        if self.fmt == 'json':
            try:
                if self.force_native_json:
                    raise ModuleNotFoundError
                import rapidjson as json
                self.dbinfo['json_module'] = 'rapidjson'
            except ModuleNotFoundError:
                self.dbinfo['json_module'] = 'json'
                import json
            self.loads = json.loads
            if dump_kwargs is None:
                dump_kwargs = {}
            self.dumps = partial(json.dumps, **dump_kwargs)
            self.suffix = '.json'
            self.read = Path.read_text
            self.write_mode = 'w'
            self.calc_digest = self._calc_hexdigest
            self.checksum_binary = False
        elif self.fmt in ['yaml', 'yml']:
            import yaml
            self.loads = yaml.safe_load
            if dump_kwargs is None:
                dump_kwargs = {'default_flow_style': False}
            self.dumps = partial(yaml.dump, **dump_kwargs)
            self.read = Path.read_text
            self.write_mode = 'w'
            self.suffix = '.yml'
            self.calc_digest = self._calc_hexdigest
            self.checksum_binary = False
        elif self.fmt == 'msgpack':
            import msgpack
            self.loads = partial(msgpack.loads, raw=False)
            if dump_kwargs is None:
                dump_kwargs = {}
            self.dumps = partial(msgpack.dumps, **dump_kwargs)
            self.suffix = '.mp'
            self.read = Path.read_bytes
            self.write_mode = 'wb'
            self.calc_digest = self._calc_digest
            self.checksum_binary = True
        elif self.fmt == 'cbor':
            import cbor
            self.loads = cbor.loads
            if dump_kwargs is None:
                dump_kwargs = {}
            self.dumps = partial(cbor.dumps, **dump_kwargs)
            self.suffix = '.cb'
            self.read = Path.read_bytes
            self.write_mode = 'wb'
            self.calc_digest = self._calc_digest
            self.checksum_binary = True
        elif self.fmt == 'pickle':
            import pickle
            self.loads = pickle.loads
            if dump_kwargs is None:
                dump_kwargs = {}
            self.dumps = partial(pickle.dumps, **dump_kwargs)
            self.suffix = '.p'
            self.read = Path.read_bytes
            self.write_mode = 'wb'
            self.calc_digest = self._calc_digest
            self.checksum_binary = True
        else:
            raise ValueError(f'Unsupported format: {self.fmt}')
        if self.checksums:
            self.suffix += 'c'
        self._suffix_len = len(self.suffix)

    def _write(self, f, data, flush=False):
        if debug:
            logger.debug(f'updating key file {f}')
        orig_file = f
        f = f.with_suffix('.tmp')
        with f.open(self.write_mode) as fh:
            fh.write(data)
            if flush or self.auto_flush:
                if debug:
                    logger.debug(f'flushing key file {f}')
                fh.flush()
                os.fsync(fh.fileno())
            f.rename(orig_file)
            if flush or self.auto_flush:
                self._sync_dirs([f.parent])

    @staticmethod
    def _sync_dirs(dirs):
        for d in dirs:
            if debug:
                logger.debug(f'syncing dir {d}')
            try:
                dirfd = os.open(d, os.O_DIRECTORY | os.O_RDONLY)
                os.fsync(dirfd)
                os.close(dirfd)
            except FileNotFoundError:
                pass

    def _calc_digest(self, s):
        from hashlib import sha256
        return sha256(s).digest()

    def _calc_hexdigest(self, s):
        from hashlib import sha256
        return sha256(s.encode()).hexdigest()

    def _load_value(self, s):
        if self.checksums:
            if self.checksum_binary:
                if self.calc_digest(s[40:]) == s[:32]:
                    return self.loads(s[40:])
                else:
                    raise ChecksumError
            else:
                checksum, date, value = s.split(maxsplit=2)
                if self.calc_digest(value) == checksum:
                    return self.loads(value)
                else:
                    raise ChecksumError
        else:
            return self.loads(s)

    def _dump_value(self, value, stime=None):
        s = self.dumps(value)
        if isinstance(s, str) and not s.endswith('\n'):
            s += '\n'
        if self.checksums:
            val = self.calc_digest(s)
            if stime is None:
                stime = time_ns()
            if self.checksum_binary:
                val += stime.to_bytes(8, 'little') + s
            else:
                val += '\n' + stime.to_bytes(8, 'little').hex() + '\n' + s
            return val
        else:
            return s

    def info(self):
        if not self._opened:
            raise RuntimeError('database is not opened')
        with self.lock:
            d = self.dbinfo.copy()
            d['repair_recommended'] = self.repair_recommended
            try:
                d.update(self.meta_info.copy())
            except:
                if debug:
                    logger.debug('no meta info')
            if debug:
                d['debug'] = True
            return d

    @staticmethod
    def _fmt_key(name):
        if name is None or name == '/':
            name = ''
        else:
            while name.startswith('/'):
                name = name[1:]
        return name

    def convert_fmt(self, new_fmt, checksums=True):
        """
        Convert database format

        Args:
            new_fmt: new format
            checksums: use checksums (default: True)
        Returns:
            Generator object with tuples (key, True|False) where True means a
            key is converted and False means a key (old-format) is purged.
        """
        with self.lock:
            if debug:
                logger.debug(f'conversion requested, '
                             f'fmt: {new_fmt}, checksums: {checksums}')
            if self._opened:
                raise RuntimeError('Can not convert opened database')
            self.open(_force_lock_ex=True)
            try:
                if new_fmt != self.fmt or checksums != self.checksums:
                    new_db = self.__class__(self.db,
                                            default_fmt=new_fmt,
                                            default_checksums=checksums)
                    new_db.open(lock_ex=False,
                                safe_write=False,
                                auto_flush=False,
                                _skip_meta=True)
                    new_db.checksums = True if checksums or \
                            checksums is None else False
                    new_db._init_meta()
                    new_db.meta_info['created'] = self.meta_info['created']
                    for key in self.list_subkeys():
                        val = self._get(key, _extended_info=True)
                        new_db.set(key, val[0], stime=val[3])
                        yield (key, True)
                    new_db._write_meta()
                    for k in new_db.purge(keep_broken=True):
                        yield (key, False)
                self.fmt = new_fmt
            finally:
                self.close()

    def _init_meta(self):
        if debug:
            logger.debug(f'creating new meta info')
        self.meta_info = {
            'fmt': self.fmt.split('/', 1)[0],
            'created': time_ns(),
            'version': DB_VERSION,
            'checksums': self.checksums
        }

    def _write_meta(self, flush=False):
        if debug:
            logger.debug(f'writing meta info file {self.meta_file}')
        import json
        with self.meta_file.open('w') as fh:
            fh.write(json.dumps(self.meta_info))
            if flush or self.auto_flush:
                fh.flush()
                os.fsync(fh.fileno())

    def open(self,
             timeout=None,
             auto_create=True,
             auto_repair=False,
             _skip_lock=False,
             _force_lock_ex=False,
             _skip_meta=False,
             **kwargs):
        """
        Args:
            timeout: max open timeout
            auto_create: automatically create db
            auto_repair: automatically repair db
            safe_write: perform safe writes (check key and write file only if
                the key is changed)
            auto_flush: always flush written data to disk
            lock_ex: lock database exclusively, so no other thread/process can
                open it (requires "portalocker" module)
        Raises:
            TimeoutError: database lock timeout
            ModuleNotFoundError: missing Python module for the chosen format
            ValueError: Unsupported format chosen
            RuntimeError: database / meta info errors
        """
        import json
        if debug:
            logger.debug(f'opening database {self.db}')
        with self.lock:
            self._parse_options(kwargs)
            if _skip_meta:
                self.checksums = self.default_checksums
                self.fmt = self.default_fmt
                self._init_db()
            else:
                try:
                    if debug:
                        logger.debug(f'loading meta info from {self.meta_file}')
                    self.meta_info = json.loads(self.meta_file.read_text())
                    self.fmt = self.meta_info['fmt']
                    self.checksums = self.meta_info['checksums']
                    self._init_db()
                except FileNotFoundError:
                    if not auto_create:
                        if debug:
                            logger.debug(f'database not initialized')
                        raise
                    if self.db.is_dir():
                        if debug:
                            logger.debug(f'no meta info file {self.meta_file}')
                        raise RuntimeError(f'Database directory {self.db} '
                                           'exists but no meta info found')
                    self.fmt = self.default_fmt
                    self.checksums = self.default_checksums
                    self._init_db()
                    self.db.mkdir(exist_ok=True)
                    self._init_meta()
                    self._write_meta()

            self.repair_recommended = False

            if (self.lock_ex and not _skip_lock) or _force_lock_ex:
                if debug:
                    logger.debug(f'locking database')
                if self.lock_file.exists():
                    self.repair_recommended = True
                self._lock_db(timeout=timeout)

            self._opened = True
            if debug:
                logger.debug(f'database opened')
                for k, v in self.info().items():
                    logger.debug(f'{self.db.name}.{k}={v}')

            if self.auto_flush:
                self._sync_dirs([self.db])

            if self.repair_recommended:
                logger.warning(f'DB {self.db} has not been closed correctly')
                if auto_repair or self.auto_repair:
                    self.do_repair()

    def _lock_db(self, timeout=None):
        import portalocker
        try:
            if debug:
                logger.debug(f'locking file {self.lock_file}')
            self._flock = portalocker.Lock(self.lock_file.as_posix(), mode='w')
            fh = self._flock.acquire(timeout=timeout)
            fh.write(str(os.getpid()))
            fh.flush()
            os.fsync(fh.fileno())
        except portalocker.exceptions.LockException:
            raise TimeoutError

    def close(self):
        if debug:
            logger.debug(f'closing database')
        with self.lock:
            if self._flock:
                if debug:
                    logger.debug(f'removing lock file {self.lock_file}')
                self._flock.release()
                try:
                    (self.db / 'db.lock').unlink()
                except FileNotFoundError:
                    pass
            self._opened = False
            if self.auto_flush:
                self._sync_dirs([self.db])

    def __enter__(self, *args, **kwargs):
        """
        Raises:
            TimeoutError
        """
        self.open(*args, **kwargs)
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def set(self, key, value, flush=False, stime=None):
        """
        Set key to value

        The key file is always overriden

        Args:
            key: key name
            value: key value
        """
        if not self._opened:
            raise RuntimeError('database is not opened')
        name = self._fmt_key(key)
        if debug:
            logger.debug(f'setting key {name}={_format_debug_value(value)}')
        with self.lock:
            if not name:
                raise ValueError('key name not specified')
            try:
                l = self._key_locks[name]
            except KeyError:
                l = threading.RLock()
                self._key_locks[name] = l
            with l:
                keypath, keyn = name.rsplit('/', 1) if '/' in name else ('',
                                                                         name)
                keydir = self.db / keypath
                keydir.mkdir(exist_ok=True, parents=True)
                key_file = keydir / (keyn + self.suffix)
                if self.safe_write:
                    try:
                        if self.get(name) == value:
                            if debug:
                                logger.debug(f'key {name} already has '
                                             f'the same value set, skipping')
                            return
                    except KeyError:
                        pass
                self._write(key_file,
                            self._dump_value(value, stime=stime),
                            flush=flush or self.auto_flush)

    def copy(self, key, dst_key, delete=False):
        """
        Copy key to new
        """
        if debug:
            logger.debug(f'copying key {key} to {dst_key}, delete: {delete}')
        with self.lock:
            value = self.get(key)
            self.set(dst_key, value)
            if delete:
                self.delete(key)

    def rename(self, key, dst_key, flush=False):
        """
        Rename key or category to new
        """
        if not self._opened:
            raise RuntimeError('database is not opened')
        if debug:
            logger.debug(f'renaming key {key} to {dst_key}')
        with self.lock:
            name = self._fmt_key(key)
            if not name:
                raise ValueError('key name not specified')
            new_name = self._fmt_key(dst_key)
            if not new_name:
                raise ValueError('key new_name not specified')
            try:
                l = self._key_locks[name]
            except KeyError:
                l = threading.RLock()
                self._key_locks[name] = l
            try:
                l2 = self._key_locks[new_name]
            except KeyError:
                l2 = threading.RLock()
                self._key_locks[new_name] = l2
            with l:
                with l2:
                    keypath, keyn = name.rsplit(
                        '/', 1) if '/' in name else ('', name)
                    keydir = self.db / keypath
                    key_file = keydir / (keyn + self.suffix)

                    keypath, keyn = new_name.rsplit(
                        '/', 1) if '/' in new_name else ('', new_name)
                    keydir = self.db / keypath
                    keydir.mkdir(exist_ok=True, parents=True)
                    dst_key_file = keydir / (keyn + self.suffix)

                    renamed = False

                    # rename key file
                    try:
                        key_file.rename(dst_key_file)
                        renamed = True
                        if flush or self.auto_flush:
                            self._sync_dirs(
                                {key_file.parent, dst_key_file.parent})
                    except FileNotFoundError:
                        pass

                    # rename dir if exists
                    d = key_file.with_suffix('')
                    dst_d = dst_key_file.with_suffix('')
                    try:
                        d.rename(dst_d)
                        if flush or self.auto_flush:
                            self._sync_dirs({d.parent, dst_d.parent})
                    except FileNotFoundError:
                        if not renamed:
                            raise KeyError(f'Key/category not found {key}')
            # remove empty dirs if exist
            self.delete(key, _dir_only=True)

    def key_exists(self, key):
        """
        Returns:
            True: if key exists
            False: if not
        """
        return self._get(key, _check_exists_only=True) if key else False

    def get(self, key, default=KeyError):
        """
        Get key value

        Args:
            key: key name
            default: default value, if the field is not present (if not
                specified, KeyError is raised)
        """
        return self._get(key, default)[0]

    def explain(self, key):
        """
        Get key value + extended info

        Args:
            name: key name

        Returns:
            dict(value, info=Path.stat, checksum=checksum, file=Path)
        """
        result = self._get(key, _extended_info=True)
        if result[0] is None:
            tp = '<null>'
        else:
            tp = result[0].__class__.__name__
        try:
            ln = len(result[0])
        except:
            ln = None
        return {
            'value': _format_debug_value(result[0]),
            'len': ln,
            'type': tp,
            'info': result[1],
            'sha256': result[2],
            'stime': result[3],
            'file': result[4].absolute(),
        }

    def _get(self,
             name,
             default=KeyError,
             _extended_info=False,
             _check_exists_only=False):
        if not self._opened:
            raise RuntimeError('database is not opened')
        name = self._fmt_key(name)
        if debug:
            logger.debug(f'reading key {name} value')
        with self.lock:
            try:
                l = self._key_locks[name]
            except KeyError:
                l = threading.RLock()
                self._key_locks[name] = l
            with l:
                keypath, keyn = name.rsplit('/', 1) if '/' in name else ('',
                                                                         name)
                keydir = self.db / keypath
                key_file = keydir / (keyn + self.suffix)
                if _check_exists_only:
                    return key_file.exists()
                else:
                    try:
                        if debug:
                            logger.debug(f'reading key {name} file {key_file}')
                        s = self.read(key_file)
                        if self.checksums and _extended_info:
                            if self.checksum_binary:
                                checksum = s[:32]
                                stime = s[32:40]
                            else:
                                checksum, stime, _ = s.split(maxsplit=2)
                                checksum = bytes.fromhex(checksum)
                                stime = bytes.fromhex(stime)
                            stime = int.from_bytes(stime, 'little')
                        else:
                            checksum = None
                            stime = None
                        return (self._load_value(s),
                                key_file.stat() if _extended_info else None,
                                checksum, stime,
                                key_file if _extended_info else None)
                    except FileNotFoundError:
                        if default is KeyError:
                            raise KeyError(f'Key not found: {name}')
                        else:
                            return (default, None)

    def key_dict(self, key):
        """
        Returns KeyDict object

        Args:
            key: key name
        """
        if not self._opened:
            raise RuntimeError('database is not opened')
        with self.lock:
            name = self._fmt_key(key)
            if not name:
                raise ValueError('key name not specified')
            try:
                l = self._key_locks[name]
            except KeyError:
                l = threading.RLock()
                self._key_locks[name] = l
            keypath, keyn = name.rsplit('/', 1) if '/' in name else ('', name)
            keydir = self.db / keypath
            keydir.mkdir(exist_ok=True, parents=True)
            key_file = keydir / (keyn + self.suffix)
            return KeyDict(name, key_file, l, self)

    def key_list(self, key):
        """
        Returns KeyList object

        Args:
            key: key name
        """
        if not self._opened:
            raise RuntimeError('database is not opened')
        with self.lock:
            name = self._fmt_key(key)
            if not name:
                raise ValueError('key name not specified')
            try:
                l = self._key_locks[name]
            except KeyError:
                l = threading.RLock()
                self._key_locks[name] = l
            keypath, keyn = name.rsplit('/', 1) if '/' in name else ('', name)
            keydir = self.db / keypath
            keydir.mkdir(exist_ok=True, parents=True)
            key_file = keydir / (keyn + self.suffix)
            return KeyList(name, key_file, l, self)

    def delete(self,
               key,
               recursive=False,
               flush=False,
               _no_flush=False,
               _dir_only=False):
        """
        Deletes key

        Args:
            key: key name
            recursive: also delete subkeys
        """
        if not self._opened:
            raise RuntimeError('database is not opened')
        name = self._fmt_key(key)
        if name == '' and not recursive:
            return
        if debug:
            logger.debug(f'deleting key {name}')
        dts = set()
        with self.lock:
            try:
                l = self._key_locks[name]
            except KeyError:
                l = threading.RLock()
                self._key_locks[name] = l
            with l:
                dn = self.db / name
                if dn.is_dir() and recursive:
                    self._delete_subkeys(name, flush=False)
                    dts.add(dn.parent)
                keypath, keyn = name.rsplit('/', 1) if '/' in name else ('',
                                                                         name)
                keydir = self.db / keypath
                key_file = keydir / (keyn + self.suffix)
                if not _dir_only:
                    try:
                        if (flush or self.auto_flush) and not _no_flush:
                            with key_file.open('wb') as fh:
                                fh.flush()
                                os.fsync(fh.fileno())
                        if debug:
                            logger.debug(f'deleting key file {key_file}')
                        key_file.unlink()
                        if (flush or self.auto_flush) and not _no_flush:
                            dts.add(key_file.parent)
                    except FileNotFoundError:
                        pass
                try:
                    del self._key_locks[name]
                except KeyError:
                    pass
                for p in [keydir] + list(keydir.parents):
                    if p == self.db:
                        break
                    try:
                        p.rmdir()
                        if flush or self.auto_flush:
                            dts.add(p.parent)
                    except OSError:
                        pass
                if (flush or self.auto_flush) and not _no_flush:
                    self._sync_dirs(dts)

    def clear(self, flush=False):
        """
        Clears database (removes everything)
        """
        if debug:
            logger.debug(f'CLEAR operation requested')
        self._delete_subkeys(flush=flush or self.auto_flush)

    def do_repair(self):
        """
        One-shot auto repair

        Calls repair and logs the details

        Returns:
            True if repair is successful, False if an error occured. Does not
            raise exceptions, as the broken database is still usable, except
            may miss some keys or they may be broken.
        """
        logger.warning(f'{self.db} repair started')
        removed = 0
        restored = 0
        try:
            for k, v in self.repair():
                if v:
                    logger.info(f'{self.db} key {k} restored')
                    restored += 1
                else:
                    logger.error(f'{self.db} key {k} is broken, removed')
                    removed += 1
            logger.warning(f'{self.db} repair completed, {restored} '
                           f'keys restored, {removed} keys removed')
            return True
        except Exception as e:
            logger.error(e)
            return False

    def repair(self, purge_after=True, flush=False):
        """
        Repairs database

        Finds temp key files and tries to repair them if they are valid.
        Requires checksums enabled 

        Args:
            purge_after: call purge after (default) - clean up and delete
                        broken keys and empty key directories

        Returns:
            Generator object with tuples (key, True|False) where True means a
            key is repaired and False means a key is purged.
        """
        if not self._opened:
            raise RuntimeError('database is not opened')
        if debug:
            logger.debug(f'repair operation requested')
        if not self.meta_info['checksums']:
            raise RuntimeError(
                'checksums are not enabled, repairing is not possible')
        # repair
        dts = set()
        with self.lock:
            # find possible valid keys
            for d in self.db.glob('**/*.tmp'):
                try:
                    self._load_value(self.read(d))
                    if debug:
                        logger.debug(f'valid temp key file found: {d}')
                    d.rename(d.with_suffix(self.suffix))
                    result = True
                except:
                    if debug:
                        logger.debug(f'broken key file found: {d}')
                    d.unlink()
                    result = False
                if flush or self.auto_flush:
                    dts.add(d.parent)
                yield (str(d)[self._dbpath_len:-4], result)
            if flush or self.auto_flush:
                self._sync_dirs(dts)
        # purge
        if purge_after:
            for key in self.purge():
                yield (key, False)
        self.repair_recommended = False

    def purge(self, keep_broken=False, flush=False):
        """
        Purges empty directories

        When keys are deleted, unnecessary directories are usually auto-purged,
        but in case of errors this method can be called to manually purge empty
        dirs

        Also deletes unnecessary files (e.g. left after format conversion) and
        checks all entries.

        Args:
            keep_broken: keys are not tested, broken keys are not removed

        Returns:
            Generator object with broken keys found and removed
        """
        if not self._opened:
            raise RuntimeError('database is not opened')
        if debug:
            logger.debug(
                f'purge operation requested, keep_broken: {keep_broken}')
        dts = set()
        with self.lock:
            # clean up files
            for d in self.db.glob('**/*'):
                if not d.is_dir() and d != self.lock_file and \
                        d != self.meta_file and d.suffix != self.suffix:
                    if debug:
                        logger.debug(f'deleting non-necessary file {d}')
                    d.unlink()
                    if flush or self.auto_flush:
                        dts.add(d.parent)
                elif d.suffix == self.suffix and not keep_broken:
                    try:
                        self._load_value(self.read(d))
                    except:
                        if debug:
                            logger.debug(f'broken key file found: {d}')
                        yield str(d)[self._dbpath_len:-self._suffix_len]
                        d.unlink()
                        if flush or self.auto_flush:
                            dts.add(d.parent)
            # clean up directories
            for d in reversed(list((self.db.glob('**')))):
                if d.is_dir():
                    try:
                        d.rmdir()
                        if flush or self.auto_flush:
                            dts.add(d.parent)
                    except OSError:
                        pass
            if flush or self.auto_flush:
                self._sync_dirs(dts)

    def check(self):
        """
        Check database

        Returns:
            Generator object with broken keys found
        """
        if not self._opened:
            raise RuntimeError('database is not opened')
        if debug:
            logger.debug(f'check operation requested')
        broken = []
        with self.lock:
            for d in self.db.glob('**/*'):
                if d.suffix == self.suffix or d.suffix == '.tmp':
                    try:
                        if d.suffix == '.tmp':
                            raise ValueError
                        self._load_value(self.read(d))
                    except:
                        if debug:
                            logger.debug(f'broken key file found: {d}')
                        yield str(d)[self._dbpath_len:-self._suffix_len]

    def list_subkeys(self, key=''):
        """
        List subkeys of the specified key

        Args:
            key: key name, if not specified, all keys are returned

        Returns:
            A generator object is returned, so the db becomes locked until all
            values are yielded. To unlock the db earlier, convert the returned
            generator into a list
        """
        if not self._opened:
            raise RuntimeError('database is not opened')
        name = self._fmt_key(key)
        with self.lock:
            for f in self.db.glob(f'{name}/**/*{self.suffix}'
                                  if name else f'**/*{self.suffix}'):
                name = f.absolute().as_posix()[self.
                                               _dbpath_len:-self._suffix_len]
                yield name

    def _delete_subkeys(self, name='', flush=False):
        if not self._opened:
            raise RuntimeError('database is not opened')
        name = self._fmt_key(name)
        import shutil
        dts = set()
        with self.lock:
            if name:
                path = self.db / name
            else:
                path = self.db
            try:
                for k in reversed(sorted(self.list_subkeys(name))):
                    self.delete(k, _no_flush=True)
                    try:
                        del self._key_locks[k]
                    except KeyError:
                        pass
                for d in path.iterdir():
                    if d.is_dir():
                        if debug:
                            logger.debug(f'deleting directory {d}')
                        shutil.rmtree(d)
                        if flush:
                            dts.add(d.parent)
                    else:
                        if d.absolute() not in [self.lock_file, self.meta_file]:
                            if debug:
                                logger.debug(f'deleting file {d}')
                            d.unlink()
                            if flush:
                                dts.add(d.parent)
                if flush or self.auto_flush:
                    self._sync_dirs(dts)
            except FileNotFoundError:
                pass

    def get_subkeys(self, key='', ignore_broken=False):
        """
        Get subkeys of the specified key and their values

        Args:
            key: key name, if not specified, all keys / values are returned
            ignore_broken: do not raise errors on broken keys

        Returns:
            A generator object is returned, so the db becomes locked until all
            values are yielded. To unlock the db earlier, convert the returned
            generator into a list

            Generated values are returned as tuples (key_name, key_value)
        """
        if not self._opened:
            raise RuntimeError('database is not opened')
        name = self._fmt_key(key)
        for key in self.list_subkeys(name):
            try:
                yield key, self.get(key)
            except:
                if not ignore_broken:
                    raise


class KeyDict:
    """
    Dictionary key object

    Warning: thread-unsafe

    Should not be used directly, better usage:

    with db.key_dict('path.to.key') as key:
        # do something

    Direct acccess to key dictionary is possible via obj.data. If any fields
    are modified during the direct access, calling obj.set_modified() is
    REQUIRED (otherwise the data will be not written back when the object is
    closed)
    """

    def __init__(self, key_name, key_file, lock, db):
        self._lock = lock
        self.key_name = key_name
        self.key_file = key_file
        self.data = None
        self._changed = False
        self.db = db

    def open(self):
        if debug:
            logger.debug(
                f'loading key dict {self.key_name} from {self.key_file}')
        self._lock.acquire()
        try:
            self.data = self.db._load_value(self.db.read(self.key_file))
        except FileNotFoundError:
            self.data = {}

    def __enter__(self):
        self.open()
        return self

    def set_modified(self):
        if debug:
            logger.debug(f'setting {self.key_name} as modified')
        self._changed = True

    def get(self, name, default=KeyError):
        """
        Get key field

        Args:
            name: field name
            default: default value, if the field is not present (if not
                specified, KeyError is raised)
        """
        try:
            return self.data[name]
        except KeyError as e:
            if default is KeyError:
                raise
            else:
                return default

    def set(self, name, value):
        """
        Set key field

        Args:
            name: field name
            value: field value
        """
        if debug:
            logger.debug(f'setting key dict {self.key_name} '
                         f'{name}={_format_debug_value(value)}')
        try:
            if self.data[name] == value:
                return
        except KeyError:
            pass
        self.data[name] = value
        self.set_modified()

    def delete(self, name):
        """
        Delete key field

        Doesn't raise any exceptions if the field is not present
        """
        if debug:
            logger.debug(f'deleting key dict {self.key_name} field {name}')
        try:
            del self.data[name]
            self.set_modified()
        except:
            pass

    def close(self, _write=True):
        if _write and self._changed:
            if not self.db.safe_write or self.db.get(self.key_name,
                                                     {}) != self.data:
                if debug:
                    logger.debug(f'requesting to update {self.key_name}')
                self.db._write(self.key_file, self.db._dump_value(self.data))
        self._lock.release()

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close(_write=exc_type is None)


class KeyList:
    """
    List key object

    Warning: thread-unsafe

    Should not be used directly, better usage:

    with db.key_list('path.to.key') as key:
        # do something

    Direct acccess to key list is possible via obj.data. If the data
    is modified during the direct access, calling obj.set_modified() is
    REQUIRED (otherwise the data will be not written back when the object is
    closed)
    """

    def __init__(self, key_name, key_file, lock, db):
        self._lock = lock
        self.key_name = key_name
        self.key_file = key_file
        self.data = None
        self._changed = False
        self.db = db

    def open(self):
        if debug:
            logger.debug(
                f'loading key list {self.key_name} from {self.key_file}')
        self._lock.acquire()
        try:
            self.data = self.db._load_value(self.db.read(self.key_file))
        except FileNotFoundError:
            self.data = []

    def __enter__(self):
        self.open()
        return self

    def set_modified(self):
        if debug:
            logger.debug(f'setting {self.key_name} as modified')
        self._changed = True

    def append(self, value):
        """
        Append value to list
        """
        if debug:
            logger.debug(f'appending key list {self.key_name} '
                         f'value {_format_debug_value(value)}')
        self.data.append(value)
        self.set_modified()

    def remove(self, value):
        """
        Remove value from list
        """
        if debug:
            logger.debug(f'removing key list {self.key_name} '
                         f'value {_format_debug_value(value)}')
        self.data.remove(value)
        self.set_modified()

    def close(self, _write=True):
        if _write and self._changed:
            if not self.db.safe_write or self.db.get(self.key_name,
                                                     {}) != self.data:
                if debug:
                    logger.debug(f'requesting to update {self.key_name}')
                self.db._write(self.key_file, self.db._dump_value(self.data))
        self._lock.release()

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close(_write=exc_type is None)
