__version__ = '0.2.3'

import setuptools

with open('README.md', 'r') as fh:
    long_description = fh.read()

setuptools.setup(
    name='yedb',
    version=__version__,
    author='Altertech',
    author_email='pr@altertech.com',
    description='Rugged embedded and client/server key/value database',
    long_description=long_description,
    long_description_content_type='text/markdown',
    url='https://github.com/alttch/yedb',
    packages=setuptools.find_packages(),
    include_package_data=True,
    license='Apache License 2.0',
    install_requires=['portalocker', 'cachetools', 'jsonschema'],
    extras_require={
        'cli': [
            'icli', 'neotermcolor', 'rapidtables', 'pyyaml', 'tqdm', 'pygments',
            'getch'
        ]
    },
    classifiers=(
        'Programming Language :: Python :: 3',
        'License :: OSI Approved :: Apache Software License',
        'Topic :: Database',
        'Topic :: Database :: Database Engines/Servers',
    ),
    scripts=['bin/yedb'])
