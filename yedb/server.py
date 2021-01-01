__version__ = '0.0.27'

PID_FILE = '/tmp/yedb-server.pid'

import yedb
import platform
import os
import time
import signal
from types import GeneratorType
from pathlib import Path

from logging.handlers import SysLogHandler

import logging

logger = logging.getLogger('yedb')

if os.getenv('DEBUG'):
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


class API:

    def index(self):

        def format_error(code, msg):
            if msg.startswith("'") and msg.endswith("'"):
                msg = msg[1:-1]
            logger.error(msg)
            return dict(jsonrpc='2.0', error=dict(code=code, message=msg))

        def safe_serialize(data):
            if isinstance(data, bytes):
                return data
            elif isinstance(data, dict):
                return {k: safe_serialize(v) for k, v in data.items()}
            elif isinstance(data, list) or isinstance(data, tuple):
                return [safe_serialize(v) for v in data]
            elif isinstance(data, bool) or isinstance(data, int) or isinstance(
                    data, float):
                return data
            else:
                return str(data)

        import cherrypy
        r = cherrypy.request
        if r.method != 'POST':
            raise cherrypy.HTTPError(405)
        ct = r.headers.get('Content-Type')
        if ct == 'application/msgpack' or ct == 'application/x-msgpack':
            req = REQ_MSGPACK
        else:
            req = REQ_JSON
        cl = int(r.headers.get('Content-Length'))
        raw = r.body.read(cl)
        if req == REQ_MSGPACK:
            import msgpack
            payload = msgpack.loads(raw, raw=False)
        elif req == REQ_JSON:
            payload = json.loads(raw)
        result = []
        for pp in payload if isinstance(payload, list) else [payload]:
            if not isinstance(pp, dict) or not pp:
                raise cherrypy.HTTPError(400, 'Invalid payload')
            elif pp.get('jsonrpc') != '2.0':
                raise cherrypy.HTTPError(400, 'Unsupported JSON RPC protocol')
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
                logger.debug(f'API request {r.remote.ip} {method} {pl}')
                if method not in METHODS:
                    raise MethodNotFound
                elif method == 'test':
                    result = dict(name='yedb', version=__version__)
                else:
                    result = getattr(self.db, method)(**p)
                if isinstance(result, GeneratorType):
                    result = list(result)
                elif method == 'explain':
                    i = result['info']
                    del result['info']
                    result['mtime'] = i.st_mtime
                    result['size'] = i.st_size
                    result['sha256'] = result['sha256'].hex()
                elif method == 'info':
                    result['host'] = f'{r.local.name}:{r.local.port}'
                if result is None:
                    result = True
                else:
                    result = safe_serialize(result)
                r = {'jsonrpc': '2.0', 'result': result, 'id': req_id}
            except InvalidRequest:
                r = format_error(-32600, 'Invalid request')
            except MethodNotFound:
                r = format_error(-32601, 'Method not found')
            except TypeError as e:
                r = format_error(-32602, str(e))
            except KeyError as e:
                r = format_error(-32001, str(e))
            except Exception as e:
                r = format_error(-32000, str(e))
                if yedb.debug:
                    import traceback
                    logger.debug(traceback.format_exc())
            if req_id is not None:
                r['id'] = req_id
                if isinstance(payload, list):
                    result.append(r)
                else:
                    result = r
        cherrypy.response.headers['Content-Type'] = ct
        if req == REQ_MSGPACK:
            return msgpack.dumps(result)
        elif req == REQ_JSON:
            return json.dumps(result).encode()


def start(host='127.0.0.1',
          port=8870,
          threads=20,
          pid_file=PID_FILE,
          disable_auto_repair=False,
          dboptions=None):

    import cherrypy

    cherrypy.server.socket_host = host
    cherrypy.server.socket_port = port
    cherrypy.server.thread_pool = threads

    if not yedb.debug:
        cherrypy.log.error_log.propagate = False
        cherrypy.log.access_log.propagate = False
        cherrypy.config.update({'environment': 'production'})

    API.index.exposed = True
    api = API()
    cherrypy.tree.mount(api)

    p = Path(pid_file)
    p.write_text(str(os.getpid()))

    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)

    with yedb.YEDB(auto_repair=not disable_auto_repair, **dboptions) as db:
        api.db = db

        cherrypy.engine.start()
        logger.info(f'YEDB server started at {host}:{port} '
                    f'({threads} threads), DB: {dboptions["dbpath"]}')
        try:
            block()
            cherrypy.engine.stop()
            logger.info(f'YEDB server stopped, DB: {dboptions["dbpath"]}')
            cherrypy.engine.exit()
        finally:
            try:
                p.unlink()
            except FileNotFoundError:
                pass


if __name__ == '__main__':
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument('DBPATH')
    ap.add_argument('-H',
                    '--host',
                    help='Host/IP to bind to',
                    default='127.0.0.1')
    ap.add_argument('-P',
                    '--port',
                    help='Port to bind to',
                    default=8870,
                    type=int)
    ap.add_argument('--pid-file', default=PID_FILE)
    ap.add_argument('--default-fmt',
                    help='Default database format',
                    choices=['json', 'yaml', 'cbor', 'msgpack', 'pickle'])
    ap.add_argument('--threads', help='Threads to use', default=20, type=int)
    ap.add_argument('--disable-auto-flush',
                    help='Disable auto flush',
                    action='store_true')
    ap.add_argument('--disable-auto-repair',
                    help='Disable auto repair',
                    action='store_true')
    a = ap.parse_args()
    start(host=a.host,
          port=a.port,
          threads=a.threads,
          pid_file=a.pid_file,
          disable_auto_repair=a.disable_auto_repair,
          dboptions=dict(default_fmt=a.default_fmt,
                         dbpath=a.DBPATH,
                         auto_flush=not a.disable_auto_flush))
