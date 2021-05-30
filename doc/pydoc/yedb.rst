
.. py:module:: yedb


.. py:exception:: ChecksumError
   :module: yedb


.. py:exception:: FieldNotFound
   :module: yedb


.. py:class:: KeyDict(db, key)
   :module: yedb

   Dictionary key object
   
   Should not be used directly, better usage:
   
   with db.key_as_dict('path.to.key') as key:
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
      

.. py:class:: KeyList(db, key)
   :module: yedb

   List key object
   
   Should not be used directly, better usage:
   
   with db.key_as_list('path.to.key') as key:
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


.. py:class:: Session(db)
   :module: yedb

   Session object, all methods except open/close are proxied to db
   
   
   .. py:method:: Session.close()
      :module: yedb
   
      Close session
      
   
   .. py:method:: Session.open()
      :module: yedb
   
      Open session
      

.. py:class:: YEDB(path, default_fmt='json', default_checksums=True, **kwargs)
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
   
   If path is specified as HTTP/HTTPS URI, the object transforms itself
   into JSON RPC client (methods, not listed at yedb.server.METHODS
   become unimplemented)
   
   :param path: database directory
   :param lock_path: lock file path (default: path / db.lock)
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
      
   
   .. py:method:: YEDB.convert_fmt(new_fmt, checksums=True)
      :module: yedb
   
      Convert database format
      
      :param new_fmt: new format
      :param checksums: use checksums (default: True)
      
      :returns: Generator object with tuples (key, True|False) where True means a
                key is converted and False means a key (old-format) is purged.
      
   
   .. py:method:: YEDB.do_repair()
      :module: yedb
   
      One-shot auto repair
      
      Calls repair and logs the details
      
      :returns: True if repair is successful, False if an error occured. Does not
                raise exceptions, as the broken database is still usable, except
                may miss some keys or they may be broken.
      
   
   .. py:method:: YEDB.key_as_dict(key)
      :module: yedb
   
      Returns KeyDict object
      
      
      Note: doesn't lock the key on client/server
      
      :param key: key name
      
   
   .. py:method:: YEDB.key_as_list(key)
      :module: yedb
   
      Returns KeyList object
      
      Note: doesn't lock the key on client/server
      
      :param key: key name
      
   
   .. py:method:: YEDB.key_copy(key, dst_key)
      :module: yedb
   
      Copy key to new
      
   
   .. py:method:: YEDB.key_delete(key)
      :module: yedb
   
      Deletes key
      
      :param key: key name
      
   
   .. py:method:: YEDB.key_delete_field(key, field)
      :module: yedb
   
      Delete key field value
      
      The key file is always overriden
      
      :param key: key name
      :param field: field name
      :param value: key value
      
   
   .. py:method:: YEDB.key_delete_recursive(key)
      :module: yedb
   
      Deletes key and its subkeys
      
      :param key: key name
      
   
   .. py:method:: YEDB.key_dump(key='')
      :module: yedb
   
      Equal to get_subkeys(ignore_broken=True, hidden=False)
      
   
   .. py:method:: YEDB.key_exists(key)
      :module: yedb
   
      :returns: if key exists
                False: if not
      :rtype: True
      
   
   .. py:method:: YEDB.key_explain(key)
      :module: yedb
   
      Get key value + extended info
      
      :param name: key name
      
      :returns: dict(value, info=Path.stat, checksum=checksum, file=Path)
      
   
   .. py:method:: YEDB.key_get(key, default=<class 'KeyError'>)
      :module: yedb
   
      Get key value
      
      :param key: key name
      :param default: default value, if the field is not present (if not
                      specified, KeyError is raised)
      
   
   .. py:method:: YEDB.key_get_field(key, field, default=<class 'KeyError'>)
      :module: yedb
   
      Get key field value
      
      :param key: key name
      :param field: key field name
      :param default: default value, if the field is not present (if not
                      specified, KeyError is raised)
      
   
   .. py:method:: YEDB.key_get_recursive(key='', _ignore_broken=False)
      :module: yedb
   
      Get subkeys of the specified key and their values (including the key
      itself)
      
      :param key: key name, if not specified, all keys / values are returned
      
      :returns: A generator object is returned, so the db becomes locked until all
                values are yielded. To unlock the db earlier, convert the returned
                generator into a list
      
                Generated values are returned as tuples (key_name, key_value)
      
   
   .. py:method:: YEDB.key_list(key='')
      :module: yedb
   
      List subkeys of the specified key (including the key itself)
      
      :param key: key name, if not specified, all keys are returned
      
      :returns: A generator object is returned, so the db becomes locked until all
                values are yielded. To unlock the db earlier, convert the returned
                generator into a list
      
   
   .. py:method:: YEDB.key_list_all(key='')
      :module: yedb
   
      List subkeys of the specified key (including the key itself), including
      hidden
      
   
   .. py:method:: YEDB.key_load(data)
      :module: yedb
   
      Loads keys
      
      Schema validations are ignored
      
      :param data: list or generator of key/value pairs (lists or tuples)
      
   
   .. py:method:: YEDB.key_rename(key, dst_key)
      :module: yedb
   
      Rename key or category to new
      
   
   .. py:method:: YEDB.key_set(key, value, _stime=None, _ignore_schema=False)
      :module: yedb
   
      Set key value
      
      The key file is always overriden
      
      :param key: key name
      :param value: key value
      
   
   .. py:method:: YEDB.key_set_field(key, field, value)
      :module: yedb
   
      Set key field value
      
      The key file is always overriden
      
      :param key: key name
      :param field: field name
      :param value: key value
      
   
   .. py:method:: YEDB.key_update(key, data)
      :module: yedb
   
      Updates dict key with values in data
      
      :param data: dict
      
   
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
      
   
   .. py:method:: YEDB.purge(_keep_broken=False)
      :module: yedb
   
      Purges empty directories
      
      When keys are deleted, unnecessary directories are usually auto-purged,
      but in case of errors this method can be called to manually purge empty
      dirs
      
      Also deletes unnecessary files (e.g. left after format conversion) and
      checks all entries.
      
      The command also clears memory cache.
      
      :returns: Generator object with broken keys found and removed
      
   
   .. py:method:: YEDB.purge_cache()
      :module: yedb
   
      Purge cache only
      
   
   .. py:method:: YEDB.repair()
      :module: yedb
   
      Repairs database
      
      Finds temp key files and tries to repair them if they are valid.
      Requires checksums enabled
      
      :returns: Generator object with tuples (key, True|False) where True means a
                key is repaired and False means a key is purged.
      
   
   .. py:method:: YEDB.safe_purge()
      :module: yedb
   
      Same as purge, but keeps broken keys
      
   
   .. py:method:: YEDB.session()
      :module: yedb
   
      Get session object
      
