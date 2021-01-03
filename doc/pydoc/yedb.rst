
.. py:module:: yedb


.. py:exception:: ChecksumError
   :module: yedb


.. py:class:: KeyDict(key_name, key_file, lock, db)
   :module: yedb

   Dictionary key object
   
   Warning: thread-unsafe
   
   Should not be used directly, better usage:
   
   with db.key_dict('path.to.key') as key:
       # do something
   
   Direct acccess to key dictionary is possible via obj.data. If any fields
   are modified during the direct access, calling obj.set_modified() is
   REQUIRED (otherwise the data will be not written back when the object is
   closed)
   
   
   .. py:method:: KeyDict.delete(name)
      :module: yedb
   
      Delete key field
      
      Doesn't raise any exceptions if the field is not present
      
   
   .. py:method:: KeyDict.get(name, default=<class 'KeyError'>)
      :module: yedb
   
      Get key field
      
      :param name: field name
      :param default: default value, if the field is not present (if not
                      specified, KeyError is raised)
      
   
   .. py:method:: KeyDict.set(name, value)
      :module: yedb
   
      Set key field
      
      :param name: field name
      :param value: field value
      

.. py:class:: KeyList(key_name, key_file, lock, db)
   :module: yedb

   List key object
   
   Warning: thread-unsafe
   
   Should not be used directly, better usage:
   
   with db.key_list('path.to.key') as key:
       # do something
   
   Direct acccess to key list is possible via obj.data. If the data
   is modified during the direct access, calling obj.set_modified() is
   REQUIRED (otherwise the data will be not written back when the object is
   closed)
   
   
   .. py:method:: KeyList.append(value)
      :module: yedb
   
      Append value to list
      
   
   .. py:method:: KeyList.remove(value)
      :module: yedb
   
      Remove value from list
      

.. py:exception:: SchemaValidationError
   :module: yedb


.. py:class:: YEDB(dbpath, default_fmt='json', default_checksums=True, **kwargs)
   :module: yedb

   File-based database
   
   The object is thread-safe
   
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
   
   :param dbpath: database directory
   :param default_fmt: default data format
   :param default_checksums: use SHA256 checksums by default
   :param timeout: server timeout (for client/server mode)
   :param http_username: http username
   :param http_password: http password
   :param http_auth: auth type (basic or digest)
   :param cache_size: item cache size
   
   
   .. py:method:: YEDB.__enter__(*args, **kwargs)
      :module: yedb
   
      :raises TimeoutError:
      
   
   .. py:method:: YEDB.check()
      :module: yedb
   
      Check database
      
      :returns: Generator object with broken keys found
      
   
   .. py:method:: YEDB.clear(flush=False)
      :module: yedb
   
      Clears database (removes everything)
      
   
   .. py:method:: YEDB.convert_fmt(new_fmt, checksums=True)
      :module: yedb
   
      Convert database format
      
      :param new_fmt: new format
      :param checksums: use checksums (default: True)
      
      :returns: Generator object with tuples (key, True|False) where True means a
                key is converted and False means a key (old-format) is purged.
      
   
   .. py:method:: YEDB.copy(key, dst_key, delete=False)
      :module: yedb
   
      Copy key to new
      
   
   .. py:method:: YEDB.delete(key, recursive=False, flush=False, _no_flush=False, _dir_only=False)
      :module: yedb
   
      Deletes key
      
      :param key: key name
      :param recursive: also delete subkeys
      
   
   .. py:method:: YEDB.do_repair()
      :module: yedb
   
      One-shot auto repair
      
      Calls repair and logs the details
      
      :returns: True if repair is successful, False if an error occured. Does not
                raise exceptions, as the broken database is still usable, except
                may miss some keys or they may be broken.
      
   
   .. py:method:: YEDB.explain(key, full_value=False)
      :module: yedb
   
      Get key value + extended info
      
      :param name: key name
      :param full_value: obtain full key value
      
      :returns: dict(value, info=Path.stat, checksum=checksum, file=Path)
      
   
   .. py:method:: YEDB.get(key, default=<class 'KeyError'>)
      :module: yedb
   
      Get key value
      
      :param key: key name
      :param default: default value, if the field is not present (if not
                      specified, KeyError is raised)
      
   
   .. py:method:: YEDB.get_subkeys(key='', ignore_broken=False, hidden=False)
      :module: yedb
   
      Get subkeys of the specified key and their values
      
      :param key: key name, if not specified, all keys / values are returned
      :param ignore_broken: do not raise errors on broken keys
      
      :returns: A generator object is returned, so the db becomes locked until all
                values are yielded. To unlock the db earlier, convert the returned
                generator into a list
      
                Generated values are returned as tuples (key_name, key_value)
      
   
   .. py:method:: YEDB.key_dict(key)
      :module: yedb
   
      Returns KeyDict object
      
      :param key: key name
      
   
   .. py:method:: YEDB.key_exists(key)
      :module: yedb
   
      :returns: if key exists
                False: if not
      :rtype: True
      
   
   .. py:method:: YEDB.key_list(key)
      :module: yedb
   
      Returns KeyList object
      
      :param key: key name
      
   
   .. py:method:: YEDB.list_subkeys(key='', hidden=False)
      :module: yedb
   
      List subkeys of the specified key
      
      :param key: key name, if not specified, all keys are returned
      
      :returns: A generator object is returned, so the db becomes locked until all
                values are yielded. To unlock the db earlier, convert the returned
                generator into a list
      
   
   .. py:method:: YEDB.open(auto_create=True, auto_repair=False, _skip_lock=False, _force_lock_ex=False, _skip_meta=False, **kwargs)
      :module: yedb
   
      :param auto_create: automatically create db
      :param auto_repair: automatically repair db
      :param auto_flush: always flush written data to disk
      :param lock_ex: lock database exclusively, so no other thread/process can
                      open it (requires "portalocker" module)
      
      :raises TimeoutError: database lock timeout
      :raises ModuleNotFoundError: missing Python module for the chosen format
      :raises ValueError: Unsupported format chosen
      :raises RuntimeError: database / meta info errors
      
   
   .. py:method:: YEDB.purge(keep_broken=False, flush=False)
      :module: yedb
   
      Purges empty directories
      
      When keys are deleted, unnecessary directories are usually auto-purged,
      but in case of errors this method can be called to manually purge empty
      dirs
      
      Also deletes unnecessary files (e.g. left after format conversion) and
      checks all entries.
      
      The command also clears memory cache.
      
      :param keep_broken: keys are not tested, broken keys are not removed
      
      :returns: Generator object with broken keys found and removed
      
   
   .. py:method:: YEDB.rename(key, dst_key, flush=False)
      :module: yedb
   
      Rename key or category to new
      
   
   .. py:method:: YEDB.repair(purge_after=True, flush=False)
      :module: yedb
   
      Repairs database
      
      Finds temp key files and tries to repair them if they are valid.
      Requires checksums enabled
      
      :param purge_after: call purge after (default) - clean up and delete
                          broken keys and empty key directories
      
      :returns: Generator object with tuples (key, True|False) where True means a
                key is repaired and False means a key is purged.
      
   
   .. py:method:: YEDB.set(key, value, flush=False, stime=None)
      :module: yedb
   
      Set key to value
      
      The key file is always overriden
      
      :param key: key name
      :param value: key value
      
