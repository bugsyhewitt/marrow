.PHONY: install test lint clean

install:
	pip install -e ".[dev]"

test:
	pytest -q

lint:
	python -m py_compile src/marrow/*.py

clean:
	find . -type d -name __pycache__ -exec rm -r {} + 2>/dev/null; true
	find . -name '*.pyc' -delete
