.PHONY: help verify lint lint-check test test-unit test-integration install-build-system build-package install-package-uploader upload-package-test upload-package

help:
	@echo "Available targets:"
	@echo "  verify                    - Run lint-check and all tests (CI-ready)"
	@echo "  lint                      - Fix linting issues and format code"
	@echo "  lint-check                - Check linting and formatting without fixing"
	@echo "  test                      - Run all tests (unit + integration)"
	@echo "  test-unit                 - Run unit tests only"
	@echo "  test-integration          - Run integration tests only"
	@echo "  install-build-system      - Install build tools"
	@echo "  build-package             - Build source distribution"
	@echo "  install-package-uploader  - Install twine for uploading"
	@echo "  upload-package-test       - Upload to TestPyPI"
	@echo "  upload-package            - Upload to PyPI"

verify:
	make lint-check && make test

lint:
	ruff check --fix; ruff format

lint-check:
	ruff check --no-fix && ruff format --check

test:
	python3 tests/test.py

test-unit:
	python3 tests/test.py --unit

test-integration:
	python3 tests/test.py --integration

install-build-system:
	python3 -m pip install --upgrade build

build-package:
	python3 -m build --sdist

install-package-uploader:
	python3 -m pip install --upgrade twine

upload-package-test:
	python3 -m twine upload --repository testpypi --verbose dist/*

upload-package:
	python3 -m twine upload --verbose dist/*
