VERSION=0.1.13

all:
	@echo "Select target"

ver:
	find . -type f -name "*.py" -exec \
			sed -i "s/^__version__ = .*/__version__ = '${VERSION}'/g" {} \;
	find ./bin -type f -exec sed -i "s/^__version__ = .*/__version__ = '${VERSION}'/g" {} \;

sver:
	sed -i "s/^YEDB_VERSION=.*/YEDB_VERSION="${VERSION}"/g" setup-server.sh

clean:
	rm -rf dist build yedb.egg-info

d: clean sdist

sdist:
	python3 setup.py sdist

build: clean build-packages

build-packages:
	python3 setup.py build

pub-pypi:
	twine upload dist/*

test:

	pytest -x -v -v ./test-main.py

docs:
	pydoc2rst doc/pydoc/tpl_yedb.rst doc/pydoc/yedb.rst /opt/yedb-py

push:
	git commit -a -m "v${VERSION}"
	git push

pub: d test docs pub-pypi sver push
