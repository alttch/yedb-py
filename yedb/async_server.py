__version__ = '0.0.38'

PID_FILE = '/tmp/yedb-server.pid'

DEFAULT_PORT = 8870

import yedb
import platform
import os
import time
import platform
import asyncio
from types import GeneratorType
from pathlib import Path

from logging.handlers import SysLogHandler

import logging

logger = logging.getLogger('yedb')


class DummyLock:

    def __enter__(self):
        pass

    def __exit__(self, type, value, traceback):
        pass


yedb.RLock = DummyLock

if os.getenv('DEBUG') == '1':
    import logging
    logging.basicConfig(level=logging.DEBUG)
    yedb.debug = True
else:
    logging.basicConfig(level=logging.INFO)

root_logger = logging.getLogger()
logger.handlers.clear()
handler = SysLogHandler(address='/dev/log')
formatter = logging.Formatter(f'%(levelname)s yedb.server %(message)s')
handler.setFormatter(formatter)
logger.handlers.append(handler)
formatter = logging.Formatter(f'%(asctime)s {platform.node()} %(levelname)s '
                              'yedb.server %(message)s')
for h in root_logger.handlers:
    h.setFormatter(formatter)

try:
    import rapidjson as json
except:
    import json

REQ_JSON = 1
REQ_MSGPACK = 2

METHODS = [
    'test', 'get', 'set', 'list_subkeys', 'get_subkeys', 'copy', 'rename',
    'key_exists', 'explain', 'delete', 'purge', 'check', 'repair', 'info'
]


def shutdown(signum, frame):
    global server_active
    server_active = False


def block():
    global server_active
    server_active = True
    while server_active:
        time.sleep(0.1)


class InvalidRequest(Exception):
    pass


class MethodNotFound(Exception):
    pass


def log_traceback():
    if yedb.debug:
        import traceback
        logger.debug(traceback.format_exc())


async def handle_jrpc(payload, remote_name):

    def format_error(code, msg):
        if msg.startswith("'") and msg.endswith("'"):
            msg = msg[1:-1]
        logger.error(msg)
        return dict(jsonrpc='2.0', error=dict(code=code, message=msg))

    def safe_serialize(data):
        if isinstance(data, dict):
            return {k: safe_serialize(v) for k, v in data.items()}
        elif isinstance(data, list) or isinstance(data, tuple):
            return [safe_serialize(v) for v in data]
        elif data is None or isinstance(data, bool) or isinstance(
                data, int) or isinstance(data, float) or isinstance(
                    data, bytes):
            return data
        else:
            return str(data)

    result = []
    for pp in payload if isinstance(payload, list) else [payload]:
        if not isinstance(pp, dict) or not pp:
            raise RuntimeError('Invalid payload')
        elif pp.get('jsonrpc') != '2.0':
            raise RuntimeError('Unsupported JSON RPC protocol')
        req_id = pp.get('id')
        method = pp.get('method')
        p = pp.get('params')
        try:
            if isinstance(p, list):
                p = p[0]
            if p is None:
                p = {}
            elif not isinstance(p, dict):
                raise InvalidRequest
            pl = {k: v for k, v in p.items() if k != 'value'}
            logger.debug(f'API request {remote_name} {method} {pl}')
            if method not in METHODS:
                raise MethodNotFound
            elif method == 'test':
                res = dict(name='yedb', version=__version__)
            else:
                res = getattr(yedb.db, method)(**p)
            if isinstance(res, GeneratorType):
                res = list(res)
            elif method == 'explain':
                i = res['info']
                del res['info']
                res['mtime'] = i.st_mtime
                res['size'] = i.st_size
                res['sha256'] = res['sha256'].hex()
            elif method == 'info':
                res['host'] = platform.node()
            if res is None and method != 'get':
                res = True
            else:
                res = safe_serialize(res)
            r = {'jsonrpc': '2.0', 'result': res, 'id': req_id}
        except InvalidRequest:
            r = format_error(-32600, 'Invalid request')
        except MethodNotFound:
            r = format_error(-32601, 'Method not found')
        except TypeError as e:
            r = format_error(-32602, str(e))
        except KeyError as e:
            r = format_error(-32001, str(e))
        except yedb.ChecksumError as e:
            r = format_error(-32002, str(e))
        except yedb.SchemaValidationError as e:
            r = format_error(-32003, str(e))
        except Exception as e:
            r = format_error(-32000, str(e))
            log_traceback()
        if req_id is not None:
            r['id'] = req_id
            if isinstance(payload, list):
                result.append(r)
            else:
                result = r
        return result


async def handle_web(request):
    from aiohttp import web

    ct = request.content_type
    if ct == 'application/msgpack' or ct == 'application/x-msgpack':
        req = REQ_MSGPACK
    else:
        req = REQ_JSON
    raw = await request.read()
    if req == REQ_MSGPACK:
        import msgpack
        payload = msgpack.loads(raw, raw=False)
    elif req == REQ_JSON:
        payload = json.loads(raw)
    try:
        result = await handle_jrpc(payload, request.remote)
    except Exception as e:
        log_traceback()
        raise web.HTTPBadRequest(reason=str(e))
    if result:
        if req == REQ_MSGPACK:
            data = msgpack.dumps(result)
        elif req == REQ_JSON:
            data = json.dumps(result).encode()
        return web.Response(body=data, content_type=ct)
    else:
        return web.Response(status=204)


async def handle_unix(reader, writer):
    import msgpack
    try:
        while True:
            data = b''
            try:
                frame = await reader.read(4)
                if not frame:
                    break
                frame_len = int.from_bytes(frame, 'little')
                while len(data) < frame_len:
                    data += await reader.read(yedb.SOCKET_BUF)
            except asyncio.TimeoutError:
                logger.error('Socket timeout error')
                return
            payload = msgpack.loads(data, raw=False)
            result = await handle_jrpc(payload, 'localhost')
            if result:
                data = msgpack.dumps(result)
                writer.write(len(data).to_bytes(4, 'little') + data)
                await writer.drain()
    except Exception as e:
        logger.error(e)
        log_traceback()
    finally:
        writer.close()


def start(bind='127.0.0.1',
          pid_file=PID_FILE,
          disable_auto_repair=False,
          dboptions=None):

    if bind.startswith('/'):
        import asyncio
        socket = Path(bind)
        try:
            socket.unlink()
        except FileNotFoundError:
            pass
        app = None
    else:
        if bind.startswith('http://') or bind.startswith('https://'):
            bind = bind[bind.find('//') + 2:]
        try:
            host, port = bind.rsplit(':', 1)
        except ValueError:
            host = bind
            port = DEFAULT_PORT
        from aiohttp import web
        app = web.Application()
        app.add_routes([web.post('/', handle_web)])
        socket = None

    p = Path(pid_file)
    p.write_text(str(os.getpid()))

    with yedb.YEDB(auto_repair=not disable_auto_repair, **dboptions) as db:
        yedb.db = db

        logger.info(f'YEDB server started at {bind}, '
                    f'DB: {dboptions["dbpath"]}')
        try:
            if app:
                web.run_app(app, host=host, port=port, access_log=None)
            else:
                loop = asyncio.get_event_loop()
                loop.run_until_complete(
                    asyncio.start_unix_server(handle_unix,
                                              path=socket.as_posix()))
                socket.chmod(0o660)
                loop.run_forever()
            logger.info(f'YEDB server stopped, DB: {dboptions["dbpath"]}')
        finally:
            try:
                p.unlink()
            except FileNotFoundError:
                pass
            try:
                if socket:
                    socket.unlink()
            except FileNotFoundError:
                pass


if __name__ == '__main__':
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument('DBPATH')
    ap.add_argument('-B',
                    '--bind',
                    help='Host/IP:port or socket path to bind to',
                    default='127.0.0.1:8870')
    ap.add_argument('--pid-file', default=PID_FILE)
    ap.add_argument('--default-fmt',
                    help='Default database format',
                    choices=['json', 'yaml', 'cbor', 'msgpack', 'pickle'])
    ap.add_argument('--disable-auto-flush',
                    help='Disable auto flush',
                    action='store_true')
    ap.add_argument('--disable-auto-repair',
                    help='Disable auto repair',
                    action='store_true')
    a = ap.parse_args()
    start(bind=a.bind,
          pid_file=a.pid_file,
          disable_auto_repair=a.disable_auto_repair,
          dboptions=dict(default_fmt=a.default_fmt,
                         dbpath=a.DBPATH,
                         auto_flush=not a.disable_auto_flush))
