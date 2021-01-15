def _bm_set_key(db, n, x, iters, threads, v):
    with db.session() as s:
        for z in range(x * int(iters / threads),
                       (x + 1) * int(iters / threads)):
            s.key_set(key=f'.benchmark/{n}/key{z}', value=v)


def _bm_get_key(db, n, x, iters, threads):
    with db.session() as s:
        for z in range(x * int(iters / threads),
                       (x + 1) * int(iters / threads)):
            s.key_get(key=f'.benchmark/{n}/key{z}')


def cli():

    import yedb

    try:
        import icli
        import neotermcolor
        import rapidtables
        import yaml
        import tqdm
        import pygments
        import getch
    except:
        print('Please manually install required CLI modules:')
        print()
        print('  pip3 install icli neotermcolor '
              'rapidtables pyyaml tqdm pygments getch')
        print()
        raise
    import sys
    import os
    import time
    from pathlib import Path
    from hashlib import sha256

    colored = neotermcolor.colored
    cprint = neotermcolor.cprint

    neotermcolor.readline_always_safe = True

    remote = False

    if os.getenv('DEBUG') == '1':
        import logging
        logging.basicConfig(level=logging.DEBUG)
        yedb.debug = True

    def print_err(text):
        text = str(text)
        if text.startswith("'") and text.endswith("'"):
            text = text[1:-1]
        cprint(text, color='red', file=sys.stderr)

    def print_warn(text):
        cprint(text, color='yellow', attrs='bold', file=sys.stderr)

    def print_tb(force=False, delay=False):
        if yedb.debug or force:
            import traceback
            print_err(traceback.format_exc())
        else:
            print_err('FAILED')
        if delay:
            getch.getch()

    def fmt_size(num, suffix='B'):
        for unit in ['', 'Ki', 'Mi', 'Gi', 'Ti', 'Pi', 'Ei', 'Zi']:
            if abs(num) < 1024.0:
                return f'{num:3.1f}{unit}{suffix}'
            num /= 1024.0
        return f'{num:.1f}Yi{suffix}'

    def fmt_time(ts, units='s'):
        from datetime import datetime
        if units == 'ms':
            ts /= 1000
        elif units == 'us':
            ts /= 1000000
        elif units == 'ns':
            ts /= 1000000000
        elif units != 's':
            raise ValueError('invalid units')
        return datetime.fromtimestamp(ts).strftime(
            '%Y-%m-%d %H:%M:%S') + ' ' + time.tzname[0]

    def val_to_boolean(val):
        if val is None:
            return False
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

    def type_name(v):
        if v is None:
            tp = '<null>'
        else:
            if isinstance(v, bool):
                tp = 'boolean'
            elif isinstance(v, float) or isinstance(v, int):
                tp = 'number'
            elif isinstance(v, str):
                tp = 'string'
            elif isinstance(v, list) or isinstance(v, tuple):
                tp = 'array'
            elif isinstance(v, dict):
                tp = 'object'
            elif isinstance(v, bytes):
                tp = 'bytes'
            else:
                tp = f'class:{result[0].__class__.__name__}'
        return tp

    def convert_value_from(value, p):
        if p == 'number':
            try:
                value = int(value)
            except:
                value = float(value)
        elif p == 'string':
            value = str(value)
            if value == '<null>':
                value = None
        elif p == 'boolean':
            value = val_to_boolean(value)
        elif p == 'json':
            if value.strip() == '' or value is None:
                value = None
            else:
                import json
                value = json.loads(value)
        elif p == 'yaml':
            if value.strip() == '' or value is None:
                value = None
            else:
                value = yaml.safe_load(value)
        return value

    options = {}

    ap = icli.ArgumentParser()

    try:
        db_dir = sys.argv[1]
        if db_dir.startswith('-'):
            raise ValueError
        elif db_dir in [
                'get',
                'cat',
                'edit',
                'explain',
                'set',
                'delete',
                'copy',
                'rename',
                'dump',
                'ls',
                'info',
                'benchmark',
                'check',
                'repair',
                'purge',
                'convert',
        ]:
            sys.argv[1] = '-h'
            raise ValueError
        if db_dir.startswith('http://') or db_dir.startswith(
                'https://') or db_dir.startswith('tcp://') or Path(
                    db_dir).is_socket() or db_dir.endswith(
                        '.sock') or db_dir.endswith('.socket'):
            options['timeout'] = 60
            # TODO variable timeout
            remote = True
            db_path = db_dir
            db_ps = db_dir.split('//', 1)[-1]
            if '@' in db_ps:
                username, host = db_ps.split('@', 1)
                if ':' in username:
                    username, password = username.split(':', 1)
                else:
                    password = ''
                db_ps = host
                options['http_username'] = username
                options['http_password'] = password
                db_path = db_path[:db_path.find('//') +
                                  2] + db_path[db_path.find('@') + 1:]
            fmt = None
        else:
            if ':' in db_dir:
                db_dir, fmt = db_dir.rsplit(':', 1)
            else:
                fmt = None
            db_ps = db_dir
            db_path = Path(db_dir)
    except:
        print('Specify URL or path[:fmt] and optional additional commands')
        print()
        db_path = None
        db_ps = None

    try:
        if db_path and not str(db_path).startswith('-'):
            del sys.argv[1]
            db = yedb.YEDB(db_path, default_fmt=fmt, **options)
        else:
            db = None
    except Exception as e:
        print_err(e)
        print_tb()
        sys.exit(1)

    class KeyCompleter:

        def __call__(self, prefix, **kwargs):
            for k in db.key_list_all(key=''):
                yield k

    class KeyGroupCompleter:

        def __call__(self, prefix, **kwargs):
            for k in db.key_list_all(key=''):
                if '/' in k:
                    c = k.split('/')
                    for i in range(len(c) + 1):
                        yield '/'.join(c[:i])
                yield k

    def pretty_print(value, raw=False, as_code=None):
        if isinstance(value, bytes):
            if sys.stdout.isatty():
                raise RuntimeError(
                    'can not write binary data to the text console')
            else:
                sys.stdout.buffer.write(value)
        elif isinstance(value, list) or (isinstance(value, dict) and raw):
            import json
            j = json.dumps(value, indent=4, sort_keys=True)
            if sys.stdout.isatty():
                from pygments import highlight, lexers, formatters
                j = highlight(j, lexers.JsonLexer(),
                              formatters.TerminalFormatter())
            print(j)
        elif isinstance(value, dict):
            pretty_print_table(
                sorted([{
                    'field': k,
                    'type': type_name(v),
                    'value': yedb._format_debug_value(v),
                } for k, v in value.items()],
                       key=lambda k: k['field']))
        else:
            if as_code == 'python' and sys.stdout.isatty():
                from pygments import highlight, lexers, formatters
                value = highlight(value, lexers.Python3Lexer(),
                                  formatters.TerminalFormatter())
            print(value)

    def pretty_print_table(data):
        if data:
            for d in data:
                for k, v in d.items():
                    if v is None:
                        d[k] = '<null>'
            from rapidtables import (format_table, FORMAT_GENERATOR,
                                     MULTILINE_ALLOW)

            header, rows = format_table(data,
                                        fmt=FORMAT_GENERATOR,
                                        multiline=MULTILINE_ALLOW)
            print(colored(header, color='blue'))
            print(colored('-' * len(header), color='grey'))
            for r in rows:
                print(r)

    def dispatcher(cmd, **kwargs):
        try:
            if cmd == 'get':
                key = kwargs.get('KEY')
                key_info = {}
                if kwargs.get('recursive'):
                    data = []
                    for k, v in db.key_get_recursive(key=key):
                        tp = type_name(v)
                        if isinstance(v, dict) or isinstance(v, list):
                            import json
                            v = json.dumps(v, sort_keys=True)
                        data.append(
                            dict(key=k,
                                 type=tp,
                                 value=v if kwargs.get('full') else
                                 yedb._format_debug_value(v)))
                    pretty_print_table(sorted(data, key=lambda k: k['key']))
                else:
                    as_raw = kwargs.get('raw')
                    if ':' in key:
                        name, field = key.rsplit(':', 1)
                        with db.key_as_dict(key=name) as kd:
                            try:
                                value = kd.get(field)
                            except KeyError:
                                print_err(
                                    f'Key field not found: {name}:{field}')
                                return
                    else:
                        try:
                            if as_raw:
                                pretty_print(db.key_get(key=key), raw=True)
                                return
                            else:
                                key_info = db.key_explain(key=key)
                                value = key_info['value']
                        except KeyError:
                            print_err(f'Key not found: {key}')
                            return
                    try:
                        if not key_info['schema'].startswith('!'):
                            schema = db.key_get(key=key_info['schema'])
                        else:
                            schema = None
                    except:
                        schema = None
                    pretty_print(value,
                                 raw=as_raw,
                                 as_code='python'
                                 if schema == {'type': 'code.python'} else None)
            elif cmd == 'cat':
                dispatcher(cmd='get', KEY=kwargs.get('KEY'), raw=True)
            elif cmd == 'server':
                db.server_set(name=kwargs.get('_option'),
                              value=yedb.val_to_boolean(kwargs.get('VALUE')))
            elif cmd == 'incr':
                print(db.key_increment(key=kwargs.get('KEY')))
            elif cmd == 'decr':
                print(db.key_decrement(key=kwargs.get('KEY')))
            elif cmd == 'dump':
                func = kwargs.get('_func')
                if func is None:
                    ap.print_help()
                elif func == 'save':
                    import msgpack
                    key = kwargs.get('KEY')
                    if kwargs.get('FILE') == '-':
                        f = None
                        if sys.stdout.isatty():
                            raise RuntimeError('stdout is a tty')
                    else:
                        f = open(kwargs.get('FILE'), 'wb')
                    fd = f if f else sys.stdout.buffer
                    c = 0
                    fd.write(b'\x01\x02')
                    try:
                        for v in db.key_dump(key=key):
                            data = msgpack.dumps(v)
                            fd.write(len(data).to_bytes(4, 'little') + data)
                            c += 1
                    finally:
                        if f:
                            f.close()
                    print(f'{c} subkey(s) of {key} dumped')
                elif func == 'load':
                    import msgpack
                    if kwargs.get('FILE') == '-':
                        f = None
                        if sys.stdin.isatty():
                            raise RuntimeError('stdin is a tty')
                    else:
                        f = open(kwargs.get('FILE'), 'rb')
                    fd = f if f else sys.stdin.buffer
                    buf = []
                    c = 0
                    x = fd.read(2)
                    if x != b'\x01\x02':
                        raise RuntimeError('Unsupported dump version')
                    try:
                        while True:
                            l = fd.read(4)
                            if not l:
                                break
                            data = msgpack.loads(fd.read(
                                int.from_bytes(l, 'little')),
                                                 raw=False)
                            buf.append(data)
                            c += 1
                            if sys.getsizeof(buf) > 32768:
                                db.key_load(data=buf)
                                buf.clear()
                        if buf:
                            db.key_load(data=buf)
                    finally:
                        if f:
                            f.close()
                    print(f'{c} key(s) loaded')
                elif func == 'view':
                    import msgpack
                    import json
                    full = kwargs.get('full')
                    if kwargs.get('FILE') == '-':
                        f = None
                        if sys.stdin.isatty():
                            raise RuntimeError('stdin is a tty')
                    else:
                        f = open(kwargs.get('FILE'), 'rb')
                    fd = f if f else sys.stdin.buffer
                    x = fd.read(2)
                    if x != b'\x01\x02':
                        raise RuntimeError('Unsupported dump version')
                    try:
                        while True:
                            l = fd.read(4)
                            if not l:
                                break
                            data = msgpack.loads(fd.read(
                                int.from_bytes(l, 'little')),
                                                 raw=False)
                            if full:
                                print(json.dumps(data))
                            else:
                                print(data[0])
                    finally:
                        if f:
                            f.close()
            elif cmd == 'copy':
                db.key_copy(key=kwargs.get('KEY'),
                            dst_key=kwargs.get('DST_KEY'))
            elif cmd == 'rename':
                db.key_rename(key=kwargs.get('KEY'),
                              dst_key=kwargs.get('DST_KEY'))
            elif cmd == 'explain':
                key = kwargs.get('KEY')
                try:
                    key_info = db.key_explain(key=key)
                except KeyError:
                    print_err(f'Key not found: {key}')
                    return
                v = key_info['value']
                if isinstance(v, dict) or isinstance(v, list):
                    import json
                    v = json.dumps(v, sort_keys=True)
                checksum = key_info['sha256']
                if checksum is None:
                    checksum = '-'
                elif isinstance(checksum, bytes):
                    checksum = checksum.hex()
                stime = key_info['stime']
                if stime is None:
                    stime = '-'
                else:
                    stime = fmt_time(stime, 'ns')
                data = [{
                    'name': 'key',
                    'value': key,
                }, {
                    'name': 'type',
                    'value': key_info['type'],
                }, {
                    'name': 'schema',
                    'value': key_info['schema'],
                }, {
                    'name': 'len',
                    'value': key_info['len'],
                }, {
                    'name': 'value',
                    'value': yedb._format_debug_value(v),
                }, {
                    'name': 'sha256',
                    'value': checksum
                }, {
                    'name': 'stime',
                    'value': stime
                }, {
                    'name': 'mtime',
                    'value': fmt_time(key_info['mtime'], 'ns')
                }, {
                    'name': 'size',
                    'value': fmt_size(key_info['size'])
                }, {
                    'name': 'file',
                    'value': key_info['file']
                }]

                pretty_print_table(sorted(data, key=lambda k: k['name']))
            elif cmd == 'edit':
                import random
                import tempfile
                key = kwargs.get('KEY')
                try:
                    key_info = db.key_explain(key=key)
                    value = key_info['value']
                except KeyError:
                    value = ''
                    key_info = {}
                if key_info.get('schema'):
                    try:
                        schema = db.key_get(key=key_info['schema'])
                    except KeyError:
                        schema = None
                else:
                    schema = None
                editor = os.getenv('EDITOR', 'vi')
                if schema == {'type': 'code.python'}:
                    suffix = '.py'
                else:
                    suffix = '.yaml'
                fname = sha256(f'{db.path}/{key}'.encode()).hexdigest()
                tmpfile = Path(f'{tempfile.gettempdir()}/{fname}.tmp{suffix}')
                if value == '':
                    tmpfile.write_text('')
                elif suffix == '.yaml':
                    tmpfile.write_text(
                        yaml.dump(value, default_flow_style=False))
                else:
                    tmpfile.write_text(value)
                try:
                    while True:
                        code = os.system(f'{editor} {tmpfile}')
                        if code:
                            print_err(f'editor exited with code {code}')
                            break
                        y = tmpfile.read_text()
                        try:
                            if suffix == '.yaml':
                                data = yaml.safe_load(y)
                            else:
                                data = y
                        except:
                            print_tb(force=True, delay=True)
                            continue
                        if data == value:
                            break
                        else:
                            try:
                                db.key_set(key=key, value=data)
                                break
                            except:
                                print_tb(force=True, delay=True)
                                continue
                finally:
                    try:
                        tmpfile.unlink()
                    except FileNotFoundError:
                        pass
            elif cmd == 'set':
                value = kwargs.get('VALUE')
                tp = kwargs.get('type')
                if value == '-':
                    if tp == 'bytes':
                        value = sys.stdin.buffer.read()
                    else:
                        value = sys.stdin.read()
                if tp != 'bytes':
                    value = convert_value_from(value, tp)
                elif isinstance(value, str):
                    value = value.encode()
                key = kwargs.get('KEY')
                if ':' in key:
                    name, field = key.rsplit(':', 1)
                    with db.key_as_dict(key=name) as kd:
                        kd.set(field, value)
                else:
                    db.key_set(key=kwargs.get('KEY'), value=value)
            elif cmd == 'delete':
                key = kwargs.get('KEY')
                if ':' in key:
                    name, field = key.rsplit(':', 1)
                    with db.key_as_dict(key=name) as kd:
                        kd.delete(field)
                else:
                    if kwargs.get('recursive'):
                        db.key_delete_recursive(key=key)
                    else:
                        db.key_delete(key=key)
            elif cmd == 'ls':
                key = kwargs.get('KEY')
                if key is None:
                    key = ''
                data = []
                for k in db.key_list_all(
                        key=key) if kwargs.get('all') else db.key_list(key=key):
                    data.append(dict(key=k))
                pretty_print_table(sorted(data, key=lambda k: k['key']))
            elif cmd == 'check':
                broken_found = False
                for k in db.check():
                    print_err(f'Key is broken: {k}')
                    broken_found = True
                if broken_found:
                    print()
                    print(
                        'Run "repair" command to clean up and fix the database')
                else:
                    cprint('OK', color='green', attrs='bold')
            elif cmd == 'repair':
                for k, r in db.repair():
                    if r:
                        cprint(f'Key restored: {k}',
                               color='green',
                               attrs='bold')
                    else:
                        print_err(f'Key removed: {k}')
            elif cmd == 'purge':
                for k in db.purge():
                    print_warn(f'Broken key REMOVED: {k}')
            elif cmd == 'convert':
                if remote:
                    db._not_implemented()
                new_fmt = kwargs.get('NEW_FORMAT')
                info = db.info()
                checksums = False if kwargs.get('disable_checksums') else True
                if info['fmt'] == new_fmt and info['checksums'] == checksums:
                    print_warn(f'Database is already in the target format')
                else:
                    print('Converting to ' + colored(new_fmt, color="yellow") +
                          ', checksums: ' +
                          colored(checksums,
                                  color="green" if checksums else "grey"))
                    from tqdm import tqdm
                    try:
                        pbar = tqdm(total=len(list(db.key_list_all(key=''))))
                        db.close()
                        for key in db.convert_fmt(new_fmt, checksums=checksums):
                            pbar.update(1)
                        pbar.close()
                        db.open()
                    except:
                        pbar.close()
                        db.open()
                        db.safe_purge()
                        raise
                    finally:
                        print('Checking...')
                        dispatcher(cmd='check')
            elif cmd == 'info':
                data = []
                info = db.info()
                for k, v in info.items():
                    if k == 'created':
                        v = fmt_time(v, 'ns')
                    data.append(dict(name=k, value=v))
                data.append(dict(name='connection', value=db.path))
                data.append(dict(name='timeout', value=db.timeout))
                if kwargs.get('full'):
                    if remote:
                        db._not_implemented()
                    db_files = [
                        f for f in info['path'].glob('**/*') if f.is_file()
                    ]
                    data.append(
                        dict(name='keys',
                             value=len([
                                 f for f in db_files if f.suffix == db.suffix
                             ])))
                    data.append(
                        dict(name='size',
                             value=fmt_size(
                                 sum(f.stat().st_size for f in db_files))))
                pretty_print_table(sorted(data, key=lambda k: k['name']))
            elif cmd == 'benchmark':

                db.key_delete_recursive(key='.benchmark')
                iters = 1000
                threads = kwargs.get('threads', 4)
                print(f'Benchmarking. Threads: {threads}')
                print()
                from concurrent.futures import ThreadPoolExecutor
                p = ThreadPoolExecutor(max_workers=threads)
                tasks = []
                test_arr = [777.777] * 100
                test_dict = {f'v{n}': n * 777.777 for n in range(100)}
                for n, v in [('number', 777.777), ('string', 'x' * 1000),
                             ('array', test_arr), ('object', test_dict)]:
                    start = time.perf_counter()

                    for i in range(threads):
                        tasks.append(
                            p.submit(_bm_set_key, db, n, i, iters, threads, v))

                    for t in tasks:
                        t.result()
                    tasks.clear()
                    print(
                        colored(
                            f'set/{n}'.ljust(12), color='blue', attrs='bold') +
                        ': {} keys/sec'.format(
                            colored(round(iters /
                                          (time.perf_counter() - start)),
                                    color='yellow')))
                print()
                db.purge_cache()
                for c in range(2):
                    for n, v in [('number', 777.777), ('string', 'x' * 1000),
                                 ('array', test_arr), ('object', test_dict)]:
                        start = time.perf_counter()
                        for z in range(threads):
                            tasks.append(
                                p.submit(_bm_get_key, db, n, i, iters, threads))

                        for t in tasks:
                            t.result()
                        tasks.clear()
                        print(
                            colored(f'get{"(cached)" if c else ""}/{n}'.ljust(
                                12),
                                    color='green',
                                    attrs='bold') +
                            ': {} keys/sec'.format(
                                colored(round(iters /
                                              (time.perf_counter() - start)),
                                        color='yellow')))
                    print()
                print('cleaning up...')
                db.key_delete_recursive(key='.benchmark')
                list(db.purge())
        except Exception as e:
            print_err(e)
            print_tb()

    need_launch = len(
        sys.argv) > 1 or not db_path or str(db_path).startswith('-')

    sp = ap.add_subparsers(dest='cmd')

    ap_get = sp.add_parser('get', help='Get key value')
    ap_get.add_argument('KEY', help='Key name or <key>:<field> for dict keys'
                       ).completer = KeyGroupCompleter()
    ap_get.add_argument('-r', '--recursive', action='store_true')
    ap_get.add_argument('-y',
                        '--full',
                        action='store_true',
                        help='Full value output when recursive')
    ap_get.add_argument('-R',
                        '--raw',
                        help='Output raw value',
                        action='store_true')

    ap_get = sp.add_parser('cat', help='Get key raw value (same as get -R)')
    ap_get.add_argument('KEY', help='Key name or <key>:<field> for dict keys'
                       ).completer = KeyCompleter()

    ap_get = sp.add_parser('incr', help='Increment numeric key')
    ap_get.add_argument('KEY', help='Key name').completer = KeyCompleter()

    ap_get = sp.add_parser('decr', help='Decrement numeric key')
    ap_get.add_argument('KEY', help='Key name').completer = KeyCompleter()

    ap_explain = sp.add_parser('explain', help='Get key extended info')
    ap_explain.add_argument('KEY').completer = KeyCompleter()

    ap_edit = sp.add_parser('edit', help='Edit key with $EDITOR')
    ap_edit.add_argument('KEY').completer = KeyCompleter()

    ap_set = sp.add_parser('set', help='Set key value')
    ap_set.add_argument('KEY', help='Key name or <key>:<field> for dict keys'
                       ).completer = KeyCompleter()
    ap_set.add_argument('VALUE', help='Value, "-" for read from stdin')
    ap_set.add_argument(
        '-p',
        '--type',
        choices=['number', 'string', 'boolean', 'json', 'yaml', 'bytes'],
        default='str')

    ap_copy = sp.add_parser('copy', help='Copy key')
    ap_copy.add_argument('KEY').completer = KeyCompleter()
    ap_copy.add_argument('DST_KEY').completer = KeyCompleter()

    ap_rename = sp.add_parser('rename', help='Rename key')
    ap_rename.add_argument('KEY').completer = KeyCompleter()
    ap_rename.add_argument('DST_KEY').completer = KeyCompleter()

    ap_delete = sp.add_parser('delete', help='Delete key')
    ap_delete.add_argument('KEY').completer = KeyGroupCompleter()
    ap_delete.add_argument('-r', '--recursive', action='store_true')

    ap_ls = sp.add_parser('ls', help='List keys')
    ap_ls.add_argument('KEY', help='Root key, optional',
                       nargs='?').completer = KeyGroupCompleter()
    ap_ls.add_argument('-a',
                       '--all',
                       action='store_true',
                       help='Include hidden')

    ap_dump = sp.add_parser('dump', help='Dump key and its subkeys')
    sp_dump = ap_dump.add_subparsers(dest='_func')

    ap_dump_save = sp_dump.add_parser('save', help='Save key dump')

    ap_dump_save.add_argument('KEY',
                              help='Key name').completer = KeyGroupCompleter()
    ap_dump_save.add_argument('FILE', help='File name ("-" for stdout)')

    ap_dump_load = sp_dump.add_parser('load', help='Load dumped keys')
    ap_dump_load.add_argument('FILE', help='File name ("-" for stdin)')

    ap_dump_view = sp_dump.add_parser('view', help='View dumped keys')
    ap_dump_view.add_argument('FILE', help='File name ("-" for stdin)')
    ap_dump_view.add_argument('-y', '--full', action='store_true')

    ap_info = sp.add_parser('info', help='Database info')
    ap_info.add_argument('-y', '--full', action='store_true')

    ap_set = sp.add_parser('server', help='Set server options')
    sp_set = ap_set.add_subparsers(dest='_option')

    ap_set_auto_flush = sp_set.add_parser('auto_flush',
                                          help='Set auto-flush mode')
    ap_set_auto_flush.add_argument('VALUE',
                                   help='Value',
                                   choices=['true', 'false'])
    ap_set_repair_recommended = sp_set.add_parser(
        'repair_recommended', help='Set repair_recommended flag')
    ap_set_repair_recommended.add_argument('VALUE',
                                           help='Value',
                                           choices=['true', 'false'])

    ap_benchmark = sp.add_parser('benchmark', help='Benchmark database')
    ap_benchmark.add_argument('--threads',
                              metavar='NUMBER',
                              type=int,
                              default=4)

    ap_check = sp.add_parser('check', help='Check database')

    ap_repair = sp.add_parser('repair', help='Repair database')

    ap_purge = sp.add_parser('purge', help='Purge database')

    ap_convert = sp.add_parser('convert', help='Convert database format')
    ap_convert.add_argument(
        'NEW_FORMAT', choices=['json', 'cbor', 'msgpack', 'yaml', 'pickle'])
    ap_convert.add_argument('--disable-checksums', action='store_true')

    ps = os.getenv('YEDB_PS', db_ps)

    ap.ps = '{}> '.format(colored(ps if ps else db_ps, color='yellow'))

    ap.run = dispatcher

    if db:
        db.open()
    try:
        if need_launch:
            ap.launch()
        else:
            if db and db.info()['repair_recommended']:
                print_warn('database has not been closed correctly, '
                           'repair is recommended')
            import readline
            history_file = os.path.expanduser('~') + '/.yedb_history'
            try:
                readline.read_history_file(history_file)
            except FileNotFoundError:
                pass
            ap.interactive()
            readline.write_history_file(history_file)

    finally:
        if db:
            db.close()
