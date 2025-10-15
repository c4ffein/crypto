.PHONY: help lint lint-check test install-build-system build-package install-package-uploader upload-package-test upload-package

help:
	@echo "Available targets:"
	@echo "  lint                      - Fix linting issues and format code"
	@echo "  lint-check                - Check linting and formatting without fixing"
	@echo "  test                      - Run tests"
	@echo "  install-build-system      - Install build tools"
	@echo "  build-package             - Build source distribution"
	@echo "  install-package-uploader  - Install twine for uploading"
	@echo "  upload-package-test       - Upload to TestPyPI"
	@echo "  upload-package            - Upload to PyPI"

lint:
	ruff check --fix; ruff format

lint-check:
	ruff check --no-fix && ruff format --check

test:
	python3 test.py

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
