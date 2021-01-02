# yedb - rugged embedded and client/server key-value database

<img src="https://img.shields.io/pypi/v/yedb.svg" /> <img src="https://img.shields.io/badge/license-Apache%202.0-green" /> <img src="https://img.shields.io/badge/python-3.6%20%7C%203.7%20%7C%203.8%20%7C%203.9-blue.svg" />

## Why YEDB?

- Is it fast?
- Fast to read, slow to write

- Is it smart?
- No

- So what is YEDB for?
- YEDB is ultra-reliable, thread-safe and very easy to use.

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
sudo mkdir /opt/yedbd
cd /opt/yedbd && curl https://raw.githubusercontent.com/alttch/yedb/main/setup-server.sh | sudo sh
```

Use env to specify extra options:

* YEDBD\_HOST - override bind host
* YEDBD\_PORT - override bind port
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
db.open(auto_repair=True)
try:
    # do some stuff
finally:
    db.close()
```

## Client/server

### Classic threaded server

(Requires manually installing "cherrypy" Python module)

```shell
# listen to localhost:8870 (default)
python3 -m yedb.server /path/to/db
```

### Async server

(Requires manually installing "aiohttp" Python module)

```shell
# listen to localhost:8870 (default)
python3 -m yedb.async_server /path/to/db
```

### Connect a client

(the built-in client requires "requests" Python module to be installed
manually)

```python
from yedb import YEDB

with YEDB('http://localhost:8870') as db:
    # do some stuff, remember to send all parameters as kwargs
```

### Building own client

YEDB uses JSON RPC (https://www.jsonrpc.org/) as the API protocol. Any method,
listed in yedb.server.METHODS can be called. Payloads can be packed either with
JSON or with MessagePack.

### Working with complicated data structures (embedded only)

```python
from yedb import YEDB

with YEDB('/path/to/db') as db:
    with db.key('path/to/keydict) as key:
        key.set('field', 'value')
    # If modified, the key is automatically saved at the end of the statement.

```

Note: key objects are thread-unsafe.

## Engine formats

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

## Database format

The format is very simple:

* .yedb - meta data file (JSON-serialized)
* path/to/key.ext - key file
* path/to/key.tmp - key didn't survive the power loss, but may be restored

By default, databases use checksums, so key files have the following formats.

For binary engine formats (msgpack, cbor, pickle):

* Byte 0-31 (32 bytes) - SHA256-checksum
* Byte 31-40 (8 bytes) - stime (key set time in nanoseconds) timestamp
* Byte 40-N - key value

For text engine formats (json, yaml):

* line 1 - SHA256-checksum (hex)
* line 2 - stime (key set time in nanoseconds) timestamp (hex)
* line 3-N - key value, with leading LF at the end

If database checksums are not used, keys are stored in the chosen serialization
format as-is. This can give benefits to easily manage / repair keys manually,
but loses data reliability, key set time (file mtime can still be used) and
using built-in repair tools.

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

https://yedb.readthedocs.io/

## TODO

* Rust library
* Dump/restore
* Transport via UNIX socket
* Softer locking & async read/writes
* Client/server complicated data structures
