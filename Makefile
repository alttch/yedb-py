VERSION=0.0.22

all:
	@echo "Select target"

ver:
	find . -type f -name "*.py" -exec \
			sed -i "s/^__version__ = .*/__version__ = '${VERSION}'/g" {} \;
	find ./bin -type f -exec sed -i "s/^__version__ = .*/__version__ = '${VERSION}'/g" {} \;

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
	pydoc2rst doc/pydoc/tpl_yedb.rst doc/pydoc/yedb.rst /opt/yedb

pub: d test docs pub-pypi
