#!/usr/bin/env python3

import glob
import os
import sys
import sh

if len(sys.argv) < 2:
    for i in glob.glob('pydoc/tpl_*.rst'):
        out = i.replace('pydoc/tpl_', 'pydoc/pydoc_')
        os.system(f'pydoc2rst {i} {out} /opt/yedb-py')
else:
    for i in sys.argv[1:]:
        os.system(
            f'pydoc2rst pydoc/tpl_{i}.rst pydoc/pydoc_{i}.rst /opt/yedb-py')
