def cli():

    import yedb

    try:
        import icli
        import neotermcolor
        import rapidtables
        import yaml
        import tqdm
        import pygments
    except:
        print('Please manually install required CLI modules:')
        print()
        print(
            '  pip3 install icli neotermcolor rapidtables pyyaml tqdm pygments')
        print()
        raise
    import sys
    import os
    from pathlib import Path

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

    def print_tb(force=False):
        if yedb.debug or force:
            import traceback
            print_err(traceback.format_exc())
        else:
            print_err('FAILED')

    def fmt_size(num, suffix='B'):
        for unit in ['', 'Ki', 'Mi', 'Gi', 'Ti', 'Pi', 'Ei', 'Zi']:
            if abs(num) < 1024.0:
                return f'{num:3.1f}{unit}{suffix}'
            num /= 1024.0
        return f'{num:.1f}Yi{suffix}'

    def fmt_time(ts, units='s'):
        from datetime import datetime
        import time
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
            tp = v.__class__.__name__
        return tp

    def convert_value_from(value, p):
        if p == 'int':
            value = int(value)
        elif p == 'float':
            value = float(value)
        elif p == 'str':
            value = str(value)
            if value == '<null>':
                value = None
        elif p == 'bool':
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
                'ls',
                'info',
                'benchmark',
                'check',
                'repair',
                'purge',
                'clear',
                'convert',
        ]:
            sys.argv[1] = '-h'
            raise ValueError
        if db_dir.startswith('http://') or db_dir.startswith('https://'):
            options['http_timeout'] = 3600
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
        print('Specify URL or dbpath[:fmt] and optional additional commands')
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
            for k in db.list_subkeys():
                yield k

    class KeyGroupCompleter:

        def __call__(self, prefix, **kwargs):
            for k in db.list_subkeys():
                if '/' in k:
                    c = k.split('/')
                    for i in range(len(c) + 1):
                        yield '/'.join(c[:i])
                yield k

    def pretty_print(value, raw=False):
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
            cprint(value, color='blue')

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
                if kwargs.get('recursive'):
                    data = []
                    for k, v in db.get_subkeys(
                            key=key, ignore_broken=kwargs.get('ignore_broken')):
                        tp = type_name(v)
                        if isinstance(v, dict) or isinstance(v, list):
                            import json
                            v = json.dumps(v, indent=4, sort_keys=True)
                        data.append(
                            dict(key=k,
                                 type=tp,
                                 value=v if kwargs.get('full') else
                                 yedb._format_debug_value(v)))
                    if db.key_exists(key=key):
                        data.append(dict(key=key, value=db.get(key=key)))
                    pretty_print_table(sorted(data, key=lambda k: k['key']))
                else:
                    if ':' in key:
                        name, field = key.rsplit(':', 1)
                        with db.key_dict(key=name) as kd:
                            try:
                                value = kd.get(field)
                            except KeyError:
                                print_err(
                                    f'Key field not found: {name}:{field}')
                                return
                    else:
                        try:
                            value = db.get(key=key)
                        except KeyError:
                            print_err(f'Key not found: {key}')
                            return
                    pretty_print(value, raw=kwargs.get('raw'))
            elif cmd == 'cat':
                dispatcher(cmd='get', KEY=kwargs.get('KEY'), raw=True)
            elif cmd == 'copy':
                db.copy(key=kwargs.get('KEY'),
                        dst_key=kwargs.get('DST_KEY'),
                        delete=kwargs.get('delete'))
            elif cmd == 'rename':
                db.rename(key=kwargs.get('KEY'), dst_key=kwargs.get('DST_KEY'))
            elif cmd == 'explain':
                key = kwargs.get('KEY')
                try:
                    key_info = db.explain(key=key)
                except KeyError:
                    print_err(f'Key not found: {key}')
                    return
                v = key_info['value']
                if isinstance(v, dict) or isinstance(v, list):
                    import json
                    v = json.dumps(v, indent=4, sort_keys=True)
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
                    'name': 'file',
                    'value': key_info['file']
                }]
                if 'info' in key_info:
                    data.append(
                        dict(name='mtime',
                             value=fmt_time(key_info['info'].st_mtime)))
                    data.append(
                        dict(name='size',
                             value=fmt_size(key_info['info'].st_size)))
                else:
                    data.append(
                        dict(name='mtime', value=fmt_time(key_info['mtime'])))
                    data.append(
                        dict(name='size', value=fmt_size(key_info['size'])))

                pretty_print_table(sorted(data, key=lambda k: k['name']))
            elif cmd == 'edit':
                import random
                import tempfile
                key = kwargs.get('KEY')
                try:
                    value = db.get(key=key)
                except KeyError:
                    value = ''
                editor = os.getenv('EDITOR', 'vi')
                tmpfile = Path(f'{tempfile.gettempdir()}'
                               f'/{random.randint(0,100000)}.tmp.yaml')
                tmpfile.write_text('' if value == '' else yaml.
                                   dump(value, default_flow_style=False))
                try:
                    while True:
                        code = os.system(f'{editor} {tmpfile}')
                        if code:
                            print_err(f'editor exited with code {code}')
                            break
                        y = tmpfile.read_text()
                        try:
                            data = yaml.safe_load(y)
                        except:
                            import time
                            print_tb(force=True)
                            time.sleep(3)
                            continue
                        if data == value:
                            break
                        else:
                            db.set(key=key, value=data)
                            break
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
                key = kwargs.get('KEY')
                if ':' in key:
                    name, field = key.rsplit(':', 1)
                    with db.key_dict(key=name) as kd:
                        kd.set(field, value)
                else:
                    db.set(key=kwargs.get('KEY'), value=value)
            elif cmd == 'delete':
                key = kwargs.get('KEY')
                if ':' in key:
                    name, field = key.rsplit(':', 1)
                    with db.key_dict(key=name) as kd:
                        kd.delete(field)
                else:
                    db.delete(key=key, recursive=kwargs.get('recursive'))
            elif cmd == 'ls':
                key = kwargs.get('KEY')
                data = []
                for k in db.list_subkeys(key=key):
                    data.append(dict(key=k))
                if db.key_exists(key=key):
                    data.append(dict(key=key))
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
            elif cmd == 'reopen':
                if remote:
                    db._not_implemented()
                db.close()
                db.open(**kwargs)
                dispatcher(cmd='info')
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
                        pbar = tqdm(total=len(list(db.list_subkeys())))
                        db.close()
                        for key in db.convert_fmt(new_fmt, checksums=checksums):
                            import time
                            pbar.update(1)
                        pbar.close()
                        db.open()
                    except:
                        pbar.close()
                        db.open()
                        db.purge(keep_broken=True)
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
                db.delete(key='.benchmark', recursive=True)
                import time
                iters = 1000
                test_arr = [777.777] * 100
                test_dict = {f'v{n}': n * 777.777 for n in range(100)}
                for n, v in [('numeric', 777.777), ('string', 'x' * 1000),
                             ('array', test_arr), ('dict', test_dict)]:
                    start = time.perf_counter()
                    for z in range(iters):
                        db.set(key=f'.benchmark/{n}/key{z}', value=v)
                    print(
                        colored(
                            f'set/{n}'.ljust(12), color='blue', attrs='bold') +
                        ': {} keys/sec'.format(
                            colored(round(iters /
                                          (time.perf_counter() - start)),
                                    color='yellow')))
                print()
                for n, v in [('numeric', 777.777), ('string', 'x' * 1000),
                             ('array', test_arr), ('dict', test_dict)]:
                    start = time.perf_counter()
                    for z in range(iters):
                        db.get(key=f'.benchmark/{n}/key{z}')
                    print(
                        colored(
                            f'get/{n}'.ljust(12), color='green', attrs='bold') +
                        ': {} keys/sec'.format(
                            colored(round(iters /
                                          (time.perf_counter() - start)),
                                    color='yellow')))
                print()
                print('cleaning up...')
                db.delete(key='.benchmark', recursive=True)
            elif cmd == 'clear':
                if remote:
                    db._not_implemented()
                if not kwargs.get('YES'):
                    print_warn('repeat the command with --YES '
                               'param to DELETE ALL database keys')
                else:
                    db.clear()
        except Exception as e:
            print_err(e)
            print_tb()

    need_launch = len(
        sys.argv) > 1 or not db_path or str(db_path).startswith('-')

    ap = icli.ArgumentParser()

    sp = ap.add_subparsers(dest='cmd')

    ap_get = sp.add_parser('get', help='Get key value')
    ap_get.add_argument('KEY', help='Key name or <key>:<field> for dict keys'
                       ).completer = KeyGroupCompleter()
    ap_get.add_argument('-r', '--recursive', action='store_true')
    ap_get.add_argument('-y',
                        '--full',
                        action='store_true',
                        help='Full value output when recursive')
    ap_get.add_argument('--ignore-broken', action='store_true')
    ap_get.add_argument('-R',
                        '--raw',
                        help='Output raw value',
                        action='store_true')

    ap_get = sp.add_parser('cat', help='Get key raw value (same as get -R)')
    ap_get.add_argument('KEY', help='Key name or <key>:<field> for dict keys'
                       ).completer = KeyCompleter()

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
        choices=['int', 'float', 'str', 'bool', 'json', 'yaml', 'bytes'],
        default='str')

    ap_copy = sp.add_parser('copy', help='Copy key')
    ap_copy.add_argument('KEY').completer = KeyCompleter()
    ap_copy.add_argument('DST_KEY').completer = KeyCompleter()
    ap_copy.add_argument('-d',
                         '--delete',
                         action='store_true',
                         help='Delete old key')

    ap_rename = sp.add_parser('rename', help='Rename key')
    ap_rename.add_argument('KEY').completer = KeyCompleter()
    ap_rename.add_argument('DST_KEY').completer = KeyCompleter()

    ap_delete = sp.add_parser('delete', help='Delete key')
    ap_delete.add_argument('KEY').completer = KeyGroupCompleter()
    ap_delete.add_argument('-r', '--recursive', action='store_true')

    ap_ls = sp.add_parser('ls', help='List keys')
    ap_ls.add_argument('KEY', help='Root key, optional',
                       nargs='?').completer = KeyCompleter()

    ap_info = sp.add_parser('info', help='Database info')
    ap_info.add_argument('-y', '--full', action='store_true')

    ap_purge = sp.add_parser('benchmark', help='Benchmark database')

    ap_check = sp.add_parser('check', help='Check database')

    ap_repair = sp.add_parser('repair', help='Repair database')

    if not need_launch:
        ap_reopen = sp.add_parser('reopen', help='Reconnect')
        ap_reopen.add_argument('-f', '--auto-flush', action='store_true')

    ap_purge = sp.add_parser('purge', help='Purge database')

    ap_clear = sp.add_parser('clear', help='Clear database')
    ap_clear.add_argument('--YES', action='store_true')

    ap_convert = sp.add_parser('convert', help='Convert database format')
    ap_convert.add_argument(
        'NEW_FORMAT', choices=['json', 'cbor', 'msgpack', 'yaml', 'pickle'])
    ap_convert.add_argument('--disable-checksums', action='store_true')

    ap.ps = '{}> '.format(colored(db_ps, color='yellow'))

    ap.run = dispatcher

    if db:
        db.open()
    try:
        if db and db.info()['repair_recommended']:
            print_warn(
                'database has not been closed correctly, repair is recommended')
        if need_launch:
            ap.launch()
        else:
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