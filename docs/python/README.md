# Python Documentation Tools

This module provides utilities for building documentation and managing your manifest for Python projects.

## Features

- Automated documentation build process
- Manifest update and management

## Usage

### Building Documentation

Use `build.py` to generate documentation for your project:

```bash
python build.py
```

This will invoke the documentation builder and create or update your docs as needed.

### Updating the Manifest

Use `update_manifest.py` to sanitize, check, update, and sort your `manifest.json` file. It reads your project name from `pyproject.toml` and ensures your manifest is up to date.

```bash
python update_manifest.py
```

You can customize the manifest and pyproject file locations with command-line arguments:

```bash
python update_manifest.py --manifest_file=custom_manifest.json --pyproject_file=custom_pyproject.toml --modules_location=custom_modules
```

## Requirements

- Python 3.12+
- `clear-skies` and `clear-skies-doc-builder` packages

## License

See `LICENSE` for details.
