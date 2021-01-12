# yedb - rugged embedded and client/server key-value database

<img src="https://img.shields.io/pypi/v/yedb.svg" /> <img src="https://img.shields.io/badge/license-Apache%202.0-green" /> <img src="https://img.shields.io/badge/python-3.6%20%7C%203.7%20%7C%203.8%20%7C%203.9-blue.svg" />

## Why YEDB?

- Is it fast?
- Fast to read, slow to write

- Is it smart?
- No

- So what is YEDB for?
- YEDB is ultra-reliable, thread-safe and very easy to use.

- I don't like Python
- There are other [implementations](https://github.com/alttch/yedb#11-implementations)

YEDB is absolutely reliable rugged key-value database, which can survive in any
power loss, unless the OS file system die. Keys data is saved in the very
reliable way and immediately flushed to disk (this can be disabled to speed
        up the engine but is not recommended - why then YEDB is used for).

* YEDB database objects are absolutely thread-safe.

* YEDB has built-in tools to automatically repair itself if any keys are broken.

* If the tools failed to help, YEDB can be easily repaired by a system
administrator, using standard Linux tools.

* YEDB can automatically validate keys with JSON Schema
(https://json-schema.org/)

* YEDB has a cool CLI

Practical usage:

* Create a database and start writing continuously

* Turn the power switch off

* Boot the machine again. The typical result: the latest saved key isn't
survived, but the database is still valid and working. In 99% of cases, the
latest key can be automatically restored with built-in repair tools.

We created YEDB to use in our embedded products as config registry trees and
rugged key-value data storage. We use it a lot and hope you'll like it too.

Note: YEDB is good on SSDs and SD cards. As it immediately syncs all the data
written, it can work on classic HDDs really slowly.

## Performance

Modern SSDs give about 200-300 keys/sec written with auto-flush enabled. The
write speed can be 10-15 times faster without it, but we would not recommend
turning auto-flush off, as it is the key feature of YEDB.

Reading speed varies:

* for embedded: 30-40k keys/second (70-100k keys/second when cached).

* for UNIX/TCP socket: 7-15k keys/second

* for HTTP: 700-800 keys/second. Transport via HTTP is mostly slow because YEDB
  client uses synchronous "requests" library (while the default server is
  async). To get better results, consider tuning the server manually and use
  a custom async client.

## Quick start

```shell
# install YEDB
pip3 install yedb

# to use as embedded or client/server - go on. to use CLI - install additional
# required libraries
pip3 install icli neotermcolor rapidtables pyyaml tqdm pygments getch

# create a new database and go interactive
yedb /path/to/my/database

# set a key
yedb set key1 value1
# get the key value
yedb get key1
```

## Quick client-server setup

```
# Install required system packages
# Debian/Ubuntu: apt-get install -y --no-install-recommends python3 python3-dev gcc
# RedHat/Fedora/CenOS: yum install -y python3 python3-devel gcc
sudo mkdir /opt/yedbd
cd /opt/yedbd && curl https://raw.githubusercontent.com/alttch/yedb-py/main/setup-server.sh | sudo sh
```

Use env to specify extra options:

* YEDBD\_BIND - override bind to (tcp://host:port, http://host:port or path to
  UNIX socket)
* YEDBD\_SERVICE - system service name
* YEDB\_PS - CLI prompt
* PIP\_EXTRA\_OPTIONS - specify pip extra options
* PYTHON - override Python path
* PIP - override pip path

## Embedding

```python
from yedb import YEDB

with YEDB('/path/to/db', auto_repair=True) as db:
    # do some stuff

# OR

db = YEDB('/path/to/db')
db.open()
try:
    # do some stuff
finally:
    db.close()
```

## Client/server

* If socket transport requested, the built-in in server requires "msgpack"
  Python module
* If HTTP transport requested, the built-in server requires "aiohttp" Python
  module

```shell
# listen to tcp://localhost:8870 (default), to bind UNIX socket, specify the
# full socket path, to use http transport, specify http://host:port to bind to
python3 -m yedb.server /path/to/db
```

### Connect a client

* If socket transport requested, the built-in in client requires "msgpack"
  Python module
* If HTTP transport requested, the built-in client requires "requests" Python
  module

```python
from yedb import YEDB

with YEDB('tcp://localhost:8870') as db:
    # do some stuff, remember to send all parameters as kwargs
```

YEDB creates thread-local objects. If the software is using permanent threads
or a thread pool, it is recommended to use sessions to correctly drop these
objects at the end of the statement:

```python
from yedb import YEDB

with YEDB('tcp://localhost:8870') as db:
    with db.session() as session:
        # do some stuff, remember to send all parameters as kwargs
        session.key_set(key='key1', value='val1')
        print(session.key_get(key='key1'))
```

### Building own client

YEDB uses JSON RPC (https://www.jsonrpc.org/) as the API protocol. Any method,
listed in yedb.server.METHODS can be called. Payloads can be packed either with
JSON or with MessagePack.

If working via UNIX or TCP socket:

* only MessagePack payload encoding is supported

* Request/response format: PROTO\_VER + DATA\_FMT + FRAME\_LEN(32-bit
  little-endian) + frame

Where PROTO\_VER = protocol version (0x01) and DATA\_FMT = data encoding format
(0x02 for MessagePack, which is the only protocol supported by the
built-in server).

### Working with complicated data structures (embedded only)

```python
from yedb import YEDB

with YEDB('/path/to/db') as db:
    with db.key_as_dict('path/to/keydict) as key:
        key.set('field', 'value')
    # If modified, the key is automatically saved at the end of the statement.
```

## Data formats

The default engine data format is JSON
(https://github.com/python-rapidjson/python-rapidjson is detected and imported
 automatically if present)

Other possible formats and their benefits:

* YAML - (requires manually installing "pyyaml" Python module) slow, but key
files are more human-readable and editable

* msgpack - (requires manually installing "msgpack" Python module). Fast,
reliable binary serialization format. If used, keys can hold binary values as
well.

* cbor - similar to msgpack (requires manually installing "cbor" Python module)

* pickle - native Python pickle binary data serialization format. Is slower
than msgpack/cbor, but keys can hold Python objects and functions as-is.

Databases can be easily converted between formats using "yedb" CLI tool or
"convert\_fmt" method, unless format-specific features are used (e.g. if keys
        have binary data, they can't be converted to JSON properly).

## YEDB Specifications and Data formats

See https://github.com/alttch/yedb

## Schema validation

As all keys are serialized values, they can be automatically schema-validated
with JSON Schema (https://json-schema.org/).

To create the validation schema for the chosen key, or key group, create a
special key ".schema/path/to", which has to contain the valid JSON Schema.

E.g. the schema, stored in the key ".schema/groups/group1" will be used for
validating all keys in "groups/group1", including the group primary key. And
the schema, stored in ".schema/groups/group1/key1" will be used for validating
"groups/group1/key1" only (if key or subgroup schema is present, the parent
        schemas are omitted).

YEDB also supports a non-standard scheme:

```json
{ "type" : "code.python" }
```

which requires the key to have valid Python code, without syntax errors.

If schema validation fails on set or structure "with" statement exit, an
exception yedb.SchemaValidationError is raised.

## Backup/restore

Full backup: simply backup the database directory with any preferred method.

Partial/server backup:

Use "dump\_keys" / "load\_keys" methods. If dump is created with CLI (requires
"msgpack" Python module for that), it has the format:

    DUMP\_VER + DUMP\_FMT

    KEY_LEN(32-bit little-endian) + KEY
    KEY_LEN(32-bit little-endian) + KEY
    KEY_LEN(32-bit little-endian) + KEY
    KEY_LEN(32-bit little-endian) + KEY
    ....
    KEY_LEN(32-bit little-endian) + KEY

## Debugging

Start client/server with DEBUG=1 env variable:

```shell
DEBUG=1 yedb /path/to/db
```

to debug when embedded, enable debug logging

```python
import yedb

yedb.debug = True
```

After, lower the default logging level.

## Module documentation

https://yedb-py.readthedocs.io/
