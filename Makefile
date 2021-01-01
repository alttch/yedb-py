VERSION=0.0.19

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

	pytest -x ./test-main.py

pub:
	d test pub-pypi
