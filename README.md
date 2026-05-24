[![CI and publish](https://github.com/xym-tool/xym/actions/workflows/workflow.yaml/badge.svg)](https://github.com/xym-tool/xym/actions/workflows/workflow.yaml)

# xym

`xym` extracts YANG modules from IETF RFCs and drafts. The source can be a local
text/RFCXML file or a URL, and extracted modules are written as `.yang` files.

## Install

Install the latest published package from PyPI:

```sh
python -m pip install xym
```

Install from a local checkout:

```sh
git clone https://github.com/xym-tool/xym.git
cd xym
python -m pip install .
```

After installation, verify the command is available:

```sh
xym --version
xym --help
```

## Usage

Extract all YANG modules from a local source file into the current directory:

```sh
xym path/to/rfc-or-draft.txt
```

Write output to a specific directory:

```sh
xym --dstdir ./yang path/to/rfc-or-draft.txt
```

Extract from a URL:

```sh
xym https://www.rfc-editor.org/rfc/rfc7223.txt
```

Use strict extraction, requiring `<CODE BEGINS>` and `<CODE ENDS>` markers:

```sh
xym --strict True path/to/rfc-or-draft.txt
```

Only extract valid example modules in strict mode:

```sh
xym --strict True --strict-examples path/to/rfc-or-draft.txt
```

Parse only selected modules:

```sh
xym --parse-only-modules ietf-interfaces example-module path/to/rfc-or-draft.txt
```

Skip selected modules:

```sh
xym --skip-modules example-module path/to/rfc-or-draft.txt
```

Check or add revisions in output filenames using pyang:

```sh
xym --force-revision-pyang path/to/rfc-or-draft.txt
```

Check or add revisions in output filenames using regular expressions:

```sh
xym --force-revision-regexp path/to/rfc-or-draft.txt
```

Parse an RFCXMLv3 source file:

```sh
xym --rfcxml path/to/rfc-or-draft.xml
```

Extract code snippets as well as YANG modules:

```sh
xym --extract-code-snippets --code-snippets-dir ./snippets path/to/rfc-or-draft.txt
```

Add source line references to extracted YANG modules:

```sh
xym --add-line-refs path/to/rfc-or-draft.txt
```

## Strict Mode

The `--strict` and `--strict-examples` options affect which modules are written:

* No strict options: all YANG modules found in the source are extracted.
* `--strict True`: only YANG modules inside `<CODE BEGINS>` and `<CODE ENDS>` are extracted.
* `--strict True --strict-examples`: only example modules outside `<CODE BEGINS>` and `<CODE ENDS>` with names starting with `example-` are extracted.

The tool prints warnings and errors for source issues that may need inspection.
For example, it reports invalid example module placement, missing revisions, and
module names that do not match output filenames.

If an output `.yang` file already exists, `xym` does not overwrite it.

## Development

This project uses Hatch for packaging, test environments, wheel building, and
version generation. Project metadata lives in `pyproject.toml`.

Install Hatch:

```sh
python -m pip install hatch
```

Show the version derived from Git tags:

```sh
hatch version
```

Run the test suite:

```sh
hatch run test:run
```

The tests include URL-based cases that fetch RFC text from the network. If those
tests fail with DNS or connection errors, rerun them with network access.

Run the installed console command inside Hatch's test environment:

```sh
hatch run test:xym --version
```

Build source and wheel distributions:

```sh
hatch build
```

Build only the wheel:

```sh
hatch build -t wheel
```

Build artifacts are written to `dist/`.

## Versioning

Versions are derived from Git tags with `hatch-vcs`. Release tags must use one
of these formats:

```text
v0.10.0
v0.10.0rc1
```

The `v` prefix is stripped from the package version. During build/install, Hatch
generates `xym/_version.py`; that file is ignored by Git and should not be
edited or committed.

## Continuous Integration

GitHub Actions are defined in `.github/workflows/workflow.yaml`.

Pull requests automatically run:

```sh
hatch run test:run
```

The workflow currently tests Python `3.10`, `3.11`, `3.12`, and `3.13`.

## Publishing

Publishing uses PyPI trusted publishing with GitHub Actions OIDC. No PyPI API
token secret is required.

Configure a trusted publisher for the PyPI project `xym` with:

* Repository owner: `xym-tool`
* Repository name: `xym`
* Workflow name: `workflow.yaml`
* Environment name: leave blank unless the workflow is later changed to use one

To publish a release wheel:

```sh
git tag v0.10.0
git push origin v0.10.0
```

To publish a release candidate wheel:

```sh
git tag v0.10.0rc1
git push origin v0.10.0rc1
```

The publish job runs only for pushed tags matching:

```text
^v[0-9]+\.[0-9]+\.[0-9]+(rc[0-9]+)?$
```

The publish job depends on the test job. If tests fail, the wheel is not
published.
