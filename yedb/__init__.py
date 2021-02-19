__version__ = '0.2.3'

DB_VERSION = 1

DEFAULT_FMT = 'json'

DEFAULT_TIMEOUT = 5

DEFAULT_CACHE_SIZE = 1000

SOCKET_BUF = 8192

FMTS = ['json', 'yaml', 'msgpack', 'cbor', 'pickle']

SERVER_ID = 'yedb-altt-py'

JSON_HEADERS = {'Content-Type': 'application/json'}
MSGPACK_HEADERS = {'Content-Type': 'application/x-msgpack'}

DB_MODE_LOCAL = 0
DB_MODE_UNIX_SOCKET = 1
DB_MODE_TCP = 2
DB_MODE_HTTP = 3

META_READ_TIMEOUT = 0.1

import threading
import jsonschema

g = threading.local()

Lock = threading.RLock

from pathlib import Path
from functools import partial
from cachetools import LRUCache

import os
import socket

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
        s = super().__str__()
        return s if s else 'Checksum error'


class SchemaValidationError(Exception):
    pass


def _format_debug_value(v):
    dv = str(v)
    if len(dv) > 79:
        dv = dv[:76] + '...'
    return dv.replace('\n', ' ').replace('\r', '').replace('\t', ' ')


def val_to_boolean(val):
    if val is None:
        return None
    elif isinstance(val, bool):
        return val
    else:
        val = str(val)
        if val.lower() in ['1', 't', 'true', 'yes', 'on', 'y']:
            return True
        elif val.lower() in ['0', 'f', 'false', 'no', 'off', 'n']:
            return False
        else:
            raise ValueError


class Session:
    """
    Session object, all methods except open/close are proxied to db
    """

    def __init__(self, db):
        self.db = db

    def __getattr__(self, name):
        return getattr(self.db, name)

    def open(self):
        """
        Open session
        """
        return

    def __enter__(self):
        # self.open()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def close(self):
        """
        Close session
        """
        try:
            g.yedb_socket.close()
        except:
            pass


class YEDB():
    """
    File-based database

    The object is thread-safe
    """

    def _init_socket(self):
        yedb_socket = socket.socket(
            socket.AF_UNIX if self.mode == DB_MODE_UNIX_SOCKET else
            socket.AF_INET, socket.SOCK_STREAM)
        yedb_socket.settimeout(self.timeout)
        yedb_socket.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 8192)
        yedb_socket.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 8192)
        return yedb_socket

    def session(self):
        """
        Get session object
        """
        return Session(self)

    def _remote_call(self, method, **kwargs):

        def _reopen_socket():
            try:
                g.yedb_socket.close()
            except:
                pass
            if debug:
                logger.debug(f'(re)opening socket {self.path}')
            yedb_socket = self._init_socket()
            yedb_socket.connect(self.path if self.mode ==
                                DB_MODE_UNIX_SOCKET else self._tcp_path)
            g.yedb_socket = yedb_socket
            return yedb_socket

        req = {'jsonrpc': '2.0', 'id': 1, 'method': method, 'params': kwargs}
        try:
            import msgpack
            use_msgpack = True
            data = msgpack.dumps(req)
        except ModuleNotFoundError:
            if self.mode != DB_MODE_HTTP:
                raise
            try:
                import rapidjson as json
            except:
                import json
            use_msgpack = False
            data = json.dumps(req)
        if debug:
            logger.debug(f'JRPC ({"msgpack" if use_msgpack else "json"}) '
                         f'{self.path} method={method} auth={self.http_auth}')
        if self.mode != DB_MODE_HTTP:
            try:
                yedb_socket = g.yedb_socket
            except AttributeError:
                yedb_socket = _reopen_socket()
            if yedb_socket._closed:
                yedb_socket = _reopen_socket()
            frame_len = 0
            exc = None
            for i in range(3):
                try:
                    t = time.perf_counter()
                    meta_limit = t + META_READ_TIMEOUT
                    req_limit = t + self.timeout
                    yedb_socket.sendall(b'\x01\x02' +
                                        len(data).to_bytes(4, 'little') + data)
                    frame = yedb_socket.recv(6)
                    while len(frame) < 6:
                        frame += yedb_socket.recv(1)
                        if time.perf_counter() > meta_limit:
                            raise TimeoutError
                    if not frame or frame[0] != 1 or frame[1] != 2:
                        raise BrokenPipeError
                    frame_len = int.from_bytes(frame[2:], 'little')
                    if frame_len == 0:
                        raise BrokenPipeError
                    response = b''
                    while len(response) < frame_len:
                        response += yedb_socket.recv(SOCKET_BUF)
                        if time.perf_counter() > req_limit:
                            raise TimeoutError
                    data = msgpack.loads(response, raw=False)
                    break
                except (BrokenPipeError, TimeoutError) as e:
                    exc = e
                    yedb_socket = _reopen_socket()
                except:
                    raise RuntimeError('Server error')
            else:
                yedb_socket.close()
                raise exc if exc else RuntimeError('Server error')
        else:
            try:
                post = g.yedb_socket.post
            except AttributeError:
                if debug:
                    logger.debug(f'(re)opening http session')
                import requests
                session = requests.Session()
                g.yedb_socket = session
                post = session.post
            # from requests import post
            r = post(self.path,
                     data=data,
                     headers=MSGPACK_HEADERS if use_msgpack else JSON_HEADERS,
                     timeout=self.timeout,
                     auth=self.http_auth)
            if not r.ok:
                raise RuntimeError(f'http response code {r.status_code}')
            if use_msgpack:
                data = msgpack.loads(r.content, raw=False)
            else:
                data = json.loads(r.text)
        try:
            error_code = data['error']['code']
        except (KeyError, TypeError):
            return data['result']
        if error_code == -32001:
            raise KeyError(data['error']['message'])
        elif error_code == -32002:
            raise ChecksumError(data['error']['message'])
        elif error_code == -32003:
            raise SchemaValidationError(data['error']['message'])
        else:
            raise RuntimeError(data['error']['message'])

    def _empty(self, *args, **kwargs):
        pass

    def _not_implemented(self, *args, **kwargs):
        raise RuntimeError('not implemented in remote mode')

    def _open_remote(self, **kwargs):
        result = self._remote_call('test')
        if result.get('name') != 'yedb':
            raise RuntimeError('unsupported RPC server')
        return result

    def _close_remote(self):
        pass

    def __init__(
        self,
        path,
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

        If path is specified as HTTP/HTTPS URI, the object transforms itself
        into JSON RPC client (methods, not listed at yedb.server.METHODS
        become unimplemented)

        Args:
            path: database directory
            lock_path: lock file path (default: path / db.lock)
            default_fmt: default data format
            default_checksums: use SHA256 checksums by default
            timeout: server timeout (for client/server mode)
            http_username: http username
            http_password: http password
            http_auth: auth type (basic or digest)
            cache_size: item cache size
        """
        path = str(path)
        self.auto_repair = kwargs.get('auto_repair')
        self.cache = LRUCache(kwargs.get('cache_size', DEFAULT_CACHE_SIZE))
        self.timeout = kwargs.get('timeout', DEFAULT_TIMEOUT)
        if debug:
            logger.debug('initializing db')
            logger.debug(f'path: {path}')
            logger.debug(f'options: {kwargs}')
        if path.startswith('http://') or path.startswith(
                'https://') or path.startswith('tcp://') or Path(
                    path).is_socket() or path.endswith(
                        '.sock') or path.endswith('.socket'):
            self.path = path
            if Path(path).is_socket() or path.endswith(
                    '.sock') or path.endswith('.socket'):
                self.mode = DB_MODE_UNIX_SOCKET
            elif path.startswith('https://') or path.startswith('http://'):
                self.mode = DB_MODE_HTTP
            else:
                self.mode = DB_MODE_TCP
                uri = path[6:].split('/', 1)[0]
                if ':' in uri:
                    host, port = uri.rsplit(':', 1)
                    self._tcp_path = (host, int(port))
                else:
                    from yedb.server import DEFAULT_PORT
                    self._tcp_path = (uri, DEFAULT_PORT)
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
                        setattr(self, f, self._open_remote)
                    elif f == 'close':
                        setattr(self, f, self._close_remote)
                    elif not f.startswith('_') and f not in [
                            'session', 'key_as_dict', 'key_as_list'
                    ]:
                        if f in METHODS:
                            setattr(self, f, partial(self._remote_call, f))
                        else:
                            setattr(self, f, self._not_implemented)
        else:
            self.lock = Lock()
            self.mode = DB_MODE_LOCAL
            self.path = Path(path).absolute()
            self.key_path = (self.path / 'keys').absolute()
            self.default_fmt = default_fmt if default_fmt else DEFAULT_FMT
            self.default_checksums = default_checksums
            self._key_path_len = len(self.key_path.absolute().as_posix()) + 1
            self._opened = False
            self._flock = None
            self._flock_fh = None
            self.lock_file = kwargs.get('lock_path',
                                        (self.path / 'db.lock').absolute())
            self.meta_file = (self.path / '.yedb').absolute()
            self.write_modified_only = True
            self.auto_flush = True
            self.lock_ex = True
            self.force_native_json = False
            self._parse_options(kwargs)

    def _find_schema(self, key):
        if key.startswith('.schema/') or key == '.schema':
            try:
                schema = self.key_get(key)
                if schema == {'type': 'code.python'}:
                    return '<Python code>', '!https://www.python.org/'
            except KeyError:
                pass
            return '<JSON Schema>', '!JSON Schema draft-7'
        while True:
            try:
                schema_key = f'.schema/{key}' if key else '.schema'
                return self.key_get(schema_key), schema_key
            except KeyError:
                pass
            if key == '':
                return None, None
            elif '/' not in key:
                key = ''
            else:
                key = key[:key.rfind('/')]

    def _validate_schema(self, key, value):
        if key.startswith('.schema/') or key == '.schema':
            if value == {'type': 'code.python'}:
                return
            if debug:
                logger.debug(f'validating {key} as JSON schema')
            try:
                jsonschema.validators.validator_for(value).check_schema(value)
            except jsonschema.exceptions.ValidationError as e:
                raise SchemaValidationError(e)
        else:
            schema, schema_key = self._find_schema(key)
            if schema:
                try:
                    if schema == {'type': 'code.python'}:
                        if debug:
                            logger.debug(f'validating key {key} with '
                                         f'schema {schema_key} as code.python')
                        compile(value, '', mode='exec')
                    else:
                        if debug:
                            logger.debug(f'validating key '
                                         f'{key} with schema {schema_key}')
                        jsonschema.validate(value, schema)
                except Exception as e:
                    raise SchemaValidationError(e)

    def _parse_options(self, options):
        for o in ['write_modified_only', 'auto_flush', 'lock_ex']:
            try:
                val = options[o]
                if val is not None:
                    setattr(self, o, options[o])
            except KeyError:
                pass

    def _init_db(self):
        self.dbinfo = {
            'lock_ex': self.lock_ex,
            'path': Path(self.path),
            'server': [SERVER_ID, __version__]
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
            self.checksum_binary = True
        else:
            raise ValueError(f'Unsupported format: {self.fmt}')
        if self.checksums:
            self.suffix += 'c'
        self._suffix_len = len(self.suffix)

    def _write(self, f, data):
        if debug:
            logger.debug(f'updating key file {f}')
        orig_file = f
        f = f.with_suffix('.tmp')
        with f.open(self.write_mode) as fh:
            fh.write(data)
            if self.auto_flush:
                if debug:
                    logger.debug(f'flushing key file {f}')
                fh.flush()
                os.fsync(fh.fileno())
            f.rename(orig_file)
            if self.auto_flush:
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
        return sha256(s if isinstance(s, bytes) else s.encode()).digest()

    def _load_value(self, s):
        if self.checksums:
            if self.checksum_binary:
                if self._calc_digest(s[40:]) == s[:32]:
                    return self.loads(s[40:])
                else:
                    raise ChecksumError
            else:
                checksum, date, value = s.split(maxsplit=2)
                if self._calc_digest(value).hex() == checksum:
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
            checksum = self._calc_digest(s)
            val = checksum if self.checksum_binary else checksum.hex()
            if stime is None:
                stime = time_ns()
            if self.checksum_binary:
                val += stime.to_bytes(8, 'little') + s
            else:
                val += '\n' + stime.to_bytes(8, 'little').hex() + '\n' + s
            return val
        else:
            return s

    def _purge_cache_by_path(self, path):
        if path != '' and not path.endswith('/'):
            path += '/'
        to_purge = set()
        with self.lock:
            for k in self.cache:
                if k.startswith(path) and k in self.cache:
                    to_purge.add(k)
            for k in to_purge:
                try:
                    del self.cache[k]
                except KeyError:
                    pass

    def info(self):
        with self.lock:
            if not self._opened:
                raise RuntimeError('database is not opened')
            d = self.dbinfo.copy()
            d['auto_flush'] = self.auto_flush
            d['repair_recommended'] = self.repair_recommended
            d['cached_keys'] = len(self.cache)
            try:
                d.update(self.meta_info.copy())
            except:
                if debug:
                    logger.debug('no meta info')
            if debug:
                d['debug'] = True
            return d

    def server_set(self, name, value):
        if name not in ['auto_flush', 'repair_recommended']:
            raise ValueError
        else:
            if debug:
                logger.debug(f'Setting server option {name}={value}')
            setattr(self, name, value)

    @staticmethod
    def _fmt_key(name):
        if name is None or name == '/':
            name = ''
        else:
            while name.startswith('/'):
                name = name[1:]
        return name.replace('../', '')

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
                    new_db = self.__class__(self.path,
                                            default_fmt=new_fmt,
                                            default_checksums=checksums)
                    new_db.open(lock_ex=False,
                                write_modified_only=False,
                                auto_flush=False,
                                _skip_meta=True)
                    new_db.checksums = True if checksums or \
                            checksums is None else False
                    new_db._init_meta()
                    new_db.meta_info['created'] = self.meta_info['created']
                    for key in self._list_subkeys(hidden=True):
                        val = self._get(key, _extended_info=True)
                        new_db.key_set(key, val[0], _stime=val[3])
                        yield (key, True)
                    new_db._write_meta()
                    for k in new_db.safe_purge():
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

    def _write_meta(self):
        if debug:
            logger.debug(f'writing meta info file {self.meta_file}')
        import json
        with self.meta_file.open('w') as fh:
            fh.write(json.dumps(self.meta_info))
            if self.auto_flush:
                fh.flush()
                os.fsync(fh.fileno())

    def open(self,
             auto_create=True,
             auto_repair=False,
             _skip_lock=False,
             _force_lock_ex=False,
             _skip_meta=False,
             **kwargs):
        """
        Args:
            auto_create: automatically create db
            auto_repair: automatically repair db
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
            logger.debug(f'opening database {self.path}')
        with self.lock:
            self.cache.clear()
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
                    if self.path.is_dir():
                        if debug:
                            logger.debug(f'no meta info file {self.meta_file}')
                        raise RuntimeError(f'Database directory {self.path} '
                                           'exists but no meta info found')
                    self.fmt = self.default_fmt
                    self.checksums = self.default_checksums
                    self._init_db()
                    self.path.mkdir(exist_ok=True)
                    self._init_meta()
                    self._write_meta()

            self.repair_recommended = False

            if (self.lock_ex and not _skip_lock) or _force_lock_ex:
                if debug:
                    logger.debug(f'locking database')
                if self.lock_file.exists():
                    self.repair_recommended = True
                self._lock_db(timeout=self.timeout)

            self._opened = True
            if debug:
                logger.debug(f'database opened')
                for k, v in self.info().items():
                    logger.debug(f'{self.path.name}.{k}={v}')

            if self.repair_recommended:
                logger.warning(f'DB {self.path} has not been closed correctly')
                if auto_repair or self.auto_repair:
                    self.do_repair()
        self.key_path.mkdir(exist_ok=True)
        if self.auto_flush:
            self._sync_dirs([self.path])

        return {'name': 'yedb', 'version': __version__}

    def _lock_db(self, timeout=None):
        import portalocker
        try:
            if debug:
                logger.debug(f'locking file {self.lock_file}')
            if self.lock_file.exists():
                self._flock = portalocker.Lock(self.lock_file.as_posix(),
                                               mode='w')
                self._flock.acquire(timeout=timeout)
                self._flock.release()
            self._flock = portalocker.Lock(self.lock_file.as_posix(), mode='w')
            fh = self._flock.acquire(timeout=0)
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
                try:
                    (self.path / 'db.lock').unlink()
                except FileNotFoundError:
                    pass
                self._flock.release()
            self._opened = False
            self.cache.clear()
            if self.auto_flush:
                self._sync_dirs([self.path])

    def __enter__(self, *args, **kwargs):
        """
        Raises:
            TimeoutError
        """
        self.open(*args, **kwargs)
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def key_set(self, key, value, _stime=None, _ignore_schema=False):
        """
        Set key to value

        The key file is always overriden

        Args:
            key: key name
            value: key value
        """
        name = self._fmt_key(key)
        if debug:
            logger.debug(f'setting key {name}={_format_debug_value(value)}')
        with self.lock:
            if not self._opened:
                raise RuntimeError('database is not opened')
            if not name:
                raise ValueError('key name not specified')
            keypath, keyn = name.rsplit('/', 1) if '/' in name else ('', name)
            keydir = self.key_path / keypath
            keydir.mkdir(exist_ok=True, parents=True)
            key_file = keydir / (keyn + self.suffix)
            if self.write_modified_only:
                try:
                    v = self.key_get(name)
                    if v == value and v.__class__ is value.__class__:
                        if debug:
                            logger.debug(f'key {name} already has '
                                         f'the same value set, skipping')
                        return
                except KeyError:
                    pass
            if not _ignore_schema:
                self._validate_schema(key, value)
            self._write(key_file, self._dump_value(value, stime=_stime))
            self.cache[key] = value

    def key_copy(self, key, dst_key):
        """
        Copy key to new
        """
        if debug:
            logger.debug(f'copying key {key} to {dst_key}')
        with self.lock:
            value = self.key_get(key)
            self.key_set(dst_key, value)

    def key_rename(self, key, dst_key):
        """
        Rename key or category to new
        """
        if debug:
            logger.debug(f'renaming key {key} to {dst_key}')
        with self.lock:
            if not self._opened:
                raise RuntimeError('database is not opened')
            name = self._fmt_key(key)
            if not name:
                raise ValueError('key name not specified')
            new_name = self._fmt_key(dst_key)
            if not new_name:
                raise ValueError('key new_name not specified')
            keypath, keyn = name.rsplit('/', 1) if '/' in name else ('', name)
            keydir = self.key_path / keypath
            key_file = keydir / (keyn + self.suffix)

            keypath, keyn = new_name.rsplit(
                '/', 1) if '/' in new_name else ('', new_name)
            keydir = self.key_path / keypath
            keydir.mkdir(exist_ok=True, parents=True)
            dst_key_file = keydir / (keyn + self.suffix)

            renamed = False

            # rename key file
            try:
                key_file.rename(dst_key_file)
                renamed = True
                if key in self.cache:
                    self.cache[dst_key] = self.cache.pop(key)
                if self.auto_flush:
                    self._sync_dirs({key_file.parent, dst_key_file.parent})
            except FileNotFoundError:
                pass

            # rename dir if exists
            d = key_file.with_suffix('')
            dst_d = dst_key_file.with_suffix('')
            try:
                d.rename(dst_d)
                self._purge_cache_by_path(key.rsplit('/', 1)[0])
                if self.auto_flush:
                    self._sync_dirs({d.parent, dst_d.parent})
            except FileNotFoundError:
                if not renamed:
                    raise KeyError(f'Key/category not found {key}')
            # remove empty dirs if exist
            self._delete(key, _dir_only=True)

    def key_exists(self, key):
        """
        Returns:
            True: if key exists
            False: if not
        """
        return self._get(key, _check_exists_only=True) if key else False

    def key_get(self, key, default=KeyError):
        """
        Get key value

        Args:
            key: key name
            default: default value, if the field is not present (if not
                specified, KeyError is raised)
        """
        return self._get(key, default)[0]

    def key_explain(self, key):
        """
        Get key value + extended info

        Args:
            name: key name

        Returns:
            dict(value, info=Path.stat, checksum=checksum, file=Path)
        """
        result = self._get(key, _extended_info=True)
        if result[0] is None:
            tp = 'null'
        else:
            if isinstance(result[0], bool):
                tp = 'boolean'
            elif isinstance(result[0], float) or isinstance(result[0], int):
                tp = 'number'
            elif isinstance(result[0], str):
                tp = 'string'
            elif isinstance(result[0], list) or isinstance(result[0], tuple):
                tp = 'array'
            elif isinstance(result[0], dict):
                tp = 'object'
            elif isinstance(result[0], bytes):
                tp = 'bytes'
            else:
                tp = f'class:{result[0].__class__.__name__}'
        try:
            ln = len(result[0])
        except:
            ln = None
        return {
            'value': result[0],
            'schema': self._find_schema(key)[1],
            'len': ln,
            'type': tp,
            'mtime': result[1].st_mtime_ns,
            'size': result[1].st_size,
            'sha256': result[2],
            'stime': result[3],
            'file': result[4].absolute(),
        }

    def _get(self,
             name,
             default=KeyError,
             _extended_info=False,
             _check_exists_only=False):
        name = self._fmt_key(name)
        if debug:
            logger.debug(f'reading key {name} value')
        with self.lock:
            if not self._opened:
                raise RuntimeError('database is not opened')
            keypath, keyn = name.rsplit('/', 1) if '/' in name else ('', name)
            keydir = self.key_path / keypath
            key_file = keydir / (keyn + self.suffix)
            if _check_exists_only:
                return name in self.cache or key_file.exists()
            else:
                try:
                    checksum = None
                    stime = None
                    if debug:
                        logger.debug(f'reading key {name} file {key_file}')
                    if not _extended_info and name in self.cache:
                        if debug:
                            logger.debug(f'found cached key {name}')
                        try:
                            value = self.cache[name]
                        except TypeError:
                            raise FileNotFoundError
                    else:
                        s = self.read(key_file)
                        if self.checksums:
                            if self.checksum_binary:
                                checksum = s[:32]
                                stime = s[32:40]
                            else:
                                checksum, stime, _ = s.split(maxsplit=2)
                                checksum = bytes.fromhex(checksum)
                                stime = bytes.fromhex(stime)
                            stime = int.from_bytes(stime, 'little')
                        value = self._load_value(s)
                        self.cache[name] = value
                    return (value, key_file.stat() if _extended_info else None,
                            checksum, stime,
                            key_file if _extended_info else None)
                except FileNotFoundError:
                    if default is KeyError:
                        raise KeyError(f'Key not found: {name}')
                    else:
                        return (default, None)

    def key_update(self, key, data):
        """
        Updates dict key with values in data

        Args:
            data: dict
        """
        with self.key_as_dict(key=key) as k:
            k.data.update(data)
            k.set_modified()

    def key_increment(self, key):
        with self.lock:
            try:
                value = self._get(key)[0]
            except KeyError:
                value = 0
            if not isinstance(value, int):
                raise ValueError(f'Unable to increment {key}')
            value += 1
            self.key_set(key, value)
            return value

    def key_decrement(self, key):
        with self.lock:
            try:
                value = self._get(key)[0]
            except KeyError:
                value = 0
            if not isinstance(value, int):
                raise ValueError(f'Unable to increment {key}')
            value -= 1
            self.key_set(key, value)
            return value

    def key_as_dict(self, key):
        """
        Returns KeyDict object


        Note: doesn't lock the key on client/server

        Args:
            key: key name
        """
        return KeyDict(self, key)

    def key_as_list(self, key):
        """
        Returns KeyList object

        Note: doesn't lock the key on client/server

        Args:
            key: key name
        """
        return KeyList(self, key)

    def key_delete(self, key):
        """
        Deletes key

        Args:
            key: key name
        """
        return self._delete(key)

    def key_delete_recursive(self, key):
        """
        Deletes key and its subkeys

        Args:
            key: key name
        """
        return self._delete(key, recursive=True)

    def _delete(self, key, recursive=False, _no_flush=False, _dir_only=False):
        name = self._fmt_key(key)
        if name == '' and not recursive:
            return
        if debug:
            logger.debug(f'deleting key {name}')
        dts = set()
        with self.lock:
            if not self._opened:
                raise RuntimeError('database is not opened')
            dn = self.key_path / name
            if dn.is_dir() and recursive:
                self._delete_subkeys(name, _no_flush=True)
                dts.add(dn.parent)
            keypath, keyn = name.rsplit('/', 1) if '/' in name else ('', name)
            keydir = self.key_path / keypath
            key_file = keydir / (keyn + self.suffix)
            if not _dir_only:
                try:
                    if (self.auto_flush) and not _no_flush:
                        with key_file.open('wb') as fh:
                            fh.flush()
                            os.fsync(fh.fileno())
                    if debug:
                        logger.debug(f'deleting key file {key_file}')
                    key_file.unlink()
                    if self.auto_flush and not _no_flush:
                        dts.add(key_file.parent)
                except FileNotFoundError:
                    pass
            try:
                del self.cache[name]
            except KeyError:
                pass
            for p in [keydir] + list(keydir.parents):
                if p == self.key_path:
                    break
                try:
                    p.rmdir()
                    self._purge_cache_by_path(
                        p.absolute().as_posix()[self._key_path_len:])
                    if self.auto_flush and not _no_flush:
                        dts.add(p.parent)
                except OSError:
                    pass
            if self.auto_flush and not _no_flush:
                self._sync_dirs(dts)

    def do_repair(self):
        """
        One-shot auto repair

        Calls repair and logs the details

        Returns:
            True if repair is successful, False if an error occured. Does not
            raise exceptions, as the broken database is still usable, except
            may miss some keys or they may be broken.
        """
        logger.warning(f'{self.path} repair started')
        removed = 0
        restored = 0
        try:
            for k, v in self.repair():
                if v:
                    logger.info(f'{self.path} key {k} restored')
                    restored += 1
                else:
                    logger.error(f'{self.path} key {k} is broken, removed')
                    removed += 1
            logger.warning(f'{self.path} repair completed, {restored} '
                           f'keys restored, {removed} keys removed')
            return True
        except Exception as e:
            logger.error(e)
            return False

    def repair(self):
        """
        Repairs database

        Finds temp key files and tries to repair them if they are valid.
        Requires checksums enabled 

        Returns:
            Generator object with tuples (key, True|False) where True means a
            key is repaired and False means a key is purged.
        """
        if debug:
            logger.debug(f'repair operation requested')
        if not self.meta_info['checksums']:
            raise RuntimeError(
                'checksums are not enabled, repairing is not possible')
        # repair
        dts = set()
        with self.lock:
            self.cache.clear()
            if not self._opened:
                raise RuntimeError('database is not opened')
            # find possible valid keys
            for d in self.key_path.glob('**/*.tmp'):
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
                if self.auto_flush:
                    dts.add(d.parent)
                yield (str(d)[self._key_path_len:-4], result)
            if self.auto_flush:
                self._sync_dirs(dts)
        # purge
        for key in self.purge():
            yield (key, False)
        self.repair_recommended = False

    def safe_purge(self):
        """
        Same as purge, but keeps broken keys
        """
        return self.purge(_keep_broken=True)

    def purge_cache(self):
        """
        Purge cache only
        """
        with self.lock:
            self.cache.clear()

    def purge(self, _keep_broken=False):
        """
        Purges empty directories

        When keys are deleted, unnecessary directories are usually auto-purged,
        but in case of errors this method can be called to manually purge empty
        dirs

        Also deletes unnecessary files (e.g. left after format conversion) and
        checks all entries.

        The command also clears memory cache.

        Returns:
            Generator object with broken keys found and removed
        """
        if debug:
            logger.debug(
                f'purge operation requested, keep_broken: {_keep_broken}')
        dts = set()
        with self.lock:
            self.cache.clear()
            if not self._opened:
                raise RuntimeError('database is not opened')
            # clean up files
            for d in self.key_path.glob('**/*'):
                if not d.is_dir() and d != self.lock_file and \
                        d != self.meta_file and d.suffix != self.suffix:
                    if debug:
                        logger.debug(f'deleting non-necessary file {d}')
                    d.unlink()
                    if self.auto_flush:
                        dts.add(d.parent)
                elif d.suffix == self.suffix and not _keep_broken:
                    try:
                        self._load_value(self.read(d))
                    except:
                        if debug:
                            logger.debug(f'broken key file found: {d}')
                        yield str(d)[self._key_path_len:-self._suffix_len]
                        d.unlink()
                        if self.auto_flush:
                            dts.add(d.parent)
            # clean up directories
            for d in reversed(sorted((self.key_path.glob('**')))):
                if d.is_dir():
                    try:
                        d.rmdir()
                        if self.auto_flush:
                            dts.add(d.parent)
                    except OSError:
                        pass
            if self.auto_flush:
                self._sync_dirs(dts)

    def check(self):
        """
        Check database

        Returns:
            Generator object with broken keys found
        """
        if debug:
            logger.debug(f'check operation requested')
        broken = []
        with self.lock:
            if not self._opened:
                raise RuntimeError('database is not opened')
            for d in self.key_path.glob('**/*'):
                if d.suffix == self.suffix or d.suffix == '.tmp':
                    try:
                        if d.suffix == '.tmp':
                            raise ValueError
                        self._load_value(self.read(d))
                    except:
                        if debug:
                            logger.debug(f'broken key file found: {d}')
                        yield str(d)[self._key_path_len:-self._suffix_len]

    def key_list(self, key=''):
        """
        List subkeys of the specified key (including the key itself)

        Args:
            key: key name, if not specified, all keys are returned

        Returns:
            A generator object is returned, so the db becomes locked until all
            values are yielded. To unlock the db earlier, convert the returned
            generator into a list
        """
        return self._list_subkeys(key=key)

    def key_list_all(self, key=''):
        """
        List subkeys of the specified key (including the key itself), including
        hidden
        """
        return self._list_subkeys(key=key, hidden=True)

    def _list_subkeys(self, key='', hidden=False):
        name = self._fmt_key(key)
        with self.lock:
            if not self._opened:
                raise RuntimeError('database is not opened')
            for f in self.key_path.glob(f'{name}/**/*{self.suffix}'
                                        if name else f'**/*{self.suffix}'):
                name = f.absolute().as_posix()[self.
                                               _key_path_len:-self._suffix_len]
                if hidden or not name.startswith('.'):
                    yield name
            if self.key_exists(key):
                yield key

    def _delete_subkeys(self, name='', _no_flush=False):
        name = self._fmt_key(name)
        import shutil
        dts = set()
        with self.lock:
            if not self._opened:
                raise RuntimeError('database is not opened')
            if name:
                path = self.key_path / name
            else:
                path = self.key_path
            try:
                for k in reversed(sorted(self._list_subkeys(name,
                                                            hidden=True))):
                    self._delete(k, _no_flush=True)
                for d in path.iterdir():
                    if d.is_dir():
                        if debug:
                            logger.debug(f'deleting directory {d}')
                        shutil.rmtree(d)
                        if self.auto_flush and not _no_flush:
                            dts.add(d.parent)
                    else:
                        if d.absolute() not in [self.lock_file, self.meta_file]:
                            if debug:
                                logger.debug(f'deleting file {d}')
                            d.unlink()
                            if self.auto_flush and not _no_flush:
                                dts.add(d.parent)
                if self.auto_flush and not _no_flush:
                    self._sync_dirs(dts)
            except FileNotFoundError:
                pass
            self._purge_cache_by_path(name)

    def key_get_recursive(self, key='', _ignore_broken=False):
        """
        Get subkeys of the specified key and their values (including the key
        itself)

        Args:
            key: key name, if not specified, all keys / values are returned

        Returns:
            A generator object is returned, so the db becomes locked until all
            values are yielded. To unlock the db earlier, convert the returned
            generator into a list

            Generated values are returned as tuples (key_name, key_value)
        """
        if not self._opened:
            raise RuntimeError('database is not opened')
        name = self._fmt_key(key)
        for key in self._list_subkeys(name, hidden=True):
            try:
                yield key, self.key_get(key)
            except:
                if not _ignore_broken:
                    raise

    def key_dump(self, key=''):
        """
        Equal to get_subkeys(ignore_broken=True, hidden=False)
        """
        return self.key_get_recursive(key=key, _ignore_broken=True)

    def key_load(self, data):
        """
        Loads keys

        Schema validations are ignored

        Args:
            data: list or generator of key/value pairs (lists or tuples)
        """
        with self.lock:
            for d in data:
                self.key_set(key=d[0], value=d[1], _ignore_schema=True)


class KeyDict:
    """
    Dictionary key object

    Should not be used directly, better usage:

    with db.key_as_dict('path.to.key') as key:
        # do something

    Direct acccess to key dictionary is possible via obj.data. If any fields
    are modified during the direct access, calling obj.set_modified() is
    REQUIRED (otherwise the data will be not written back when the object is
    closed)
    """

    def __init__(self, db, key):
        self.key = key
        self.db = db
        self.data = None
        self._changed = False

    def open(self):
        try:
            self.data = self.db.key_get(key=self.key)
        except KeyError:
            self.data = {}

    def __enter__(self):
        self.open()
        return self

    def set_modified(self):
        if debug:
            logger.debug(f'setting {self.key} as modified')
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
            logger.debug(f'setting key dict {self.key} '
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
            logger.debug(f'deleting key dict {self.key} field {name}')
        try:
            del self.data[name]
            self.set_modified()
        except:
            pass

    def close(self, _write=True):
        if _write and self._changed:
            self.db.key_set(key=self.key, value=self.data)

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close(_write=exc_type is None)


class KeyList:
    """
    List key object

    Should not be used directly, better usage:

    with db.key_as_list('path.to.key') as key:
        # do something

    Direct acccess to key list is possible via obj.data. If the data
    is modified during the direct access, calling obj.set_modified() is
    REQUIRED (otherwise the data will be not written back when the object is
    closed)
    """

    def __init__(self, db, key):
        self.key = key
        self.db = db
        self.data = None
        self._changed = False

    def open(self):
        try:
            self.data = self.db.key_get(key=self.key)
        except KeyError:
            self.data = []

    def __enter__(self):
        self.open()
        return self

    def set_modified(self):
        if debug:
            logger.debug(f'setting {self.key} as modified')
        self._changed = True

    def append(self, value):
        """
        Append value to list
        """
        if debug:
            logger.debug(f'appending key list {self.key} '
                         f'value {_format_debug_value(value)}')
        self.data.append(value)
        self.set_modified()

    def remove(self, value):
        """
        Remove value from list
        """
        if debug:
            logger.debug(f'removing key list {self.key} '
                         f'value {_format_debug_value(value)}')
        self.data.remove(value)
        self.set_modified()

    def close(self, _write=True):
        if _write and self._changed:
            self.db.key_set(key=self.key, value=self.data)

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close(_write=exc_type is None)
