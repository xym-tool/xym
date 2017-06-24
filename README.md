[![Build Status](https://travis-ci.org/xym-tool/xym.svg)](https://travis-ci.org/xym-tool/xym)

# xym.py

xym is a simple utility for extracting [YANG](https://tools.ietf.org/rfc/rfc6020.txt) modules from files.

xym may be installed via PyPi, or the latest version may be picked up from here and manually installed (along with its dependencies). It can often be sensible to install tools into a virtualenv, which is recommended. For example:

```
$ git clone https://github.com/xym-tool/xym.git
Cloning into 'xym'...
remote: Counting objects: 32, done.
remote: Compressing objects: 100% (20/20), done.
remote: Total 32 (delta 8), reused 29 (delta 5), pack-reused 0
Unpacking objects: 100% (32/32), done.
Checking connectivity... done.
$ cd xym
$ virtualenv v
New python executable in v/bin/python2.7
Not overwriting existing python script v/bin/python (you must use v/bin/python2.7)
Installing setuptools, pip, wheel...done.
$ . v/bin/activate
$ python setup.py install
running install
...
...
Finished processing dependencies for xym==0.2
$
```

Help with it's options may be displayed thus:

```
$ xym --help
usage: xym [-h] [--srcdir SRCDIR] [--dstdir DSTDIR] [--strict STRICT]
           [--strict-examples] [--write-dict] [--debug DEBUG]
           [--force-revision FORCE_REVISION] [--version]
           source

Extracts one or more yang models from an IETF RFC/draft text file

positional arguments:
  source             The URL or file name of the RFC/draft text from which to
                     get the model

optional arguments:
  -h, --help         show this help message and exit
  --srcdir SRCDIR    Optional: directory where to find the source text;
                     default is './'
  --dstdir DSTDIR    Optional: directory where to put the extracted yang
                     module(s); default is './'
  --strict           Optional flag that determines syntax enforcement; If set
                     to 'True', the <CODE BEGINS> / <CODE ENDS> tags are
                     required; default is 'False'
  --strict-examples  Only output valid examples when in strict mode
  --force-revision   Optional: if True it will check if file contains 
                     correct revision in file name. If it doesnt it will
                     automatically add the correct revision to the filename
  --debug DEBUG      Optional: debug level - determines the amount of debug
                     info printed to console; default is 0 (no debug info
                     printed)
  --version          show program's version number and exit
```

The following behavior is implemented with respect to the "strict" and "strict-exmaples" options (none of the other options influence this behavior):

* No options -- all yang modules found in the source file will be extracted and yang files created.
* ```--strict``` -- only yang modules bracketed by \<CODE BEGINS\> and \<CODE-ENDS\> will be extracted
* ```--strict --strict-examples``` -- only yang module **outside** of \<CODE BEGINS\> and \<CODE-ENDS\> **and** with a name starting with "example-" will be extracted.

Please note:

* Some errors will be generated to aid in debugging the content of modules. For example:

```
ERROR: 'test-file.txt', Line 21 - Yang module 'ex-error' with no <CODE BEGINS> and not starting with 'example-'
ERROR: 'test-file.txt', Line 47 - Yang module 'example-error' with <CODE BEGINS> and starting with 'example-'
```

* If any yang modules that will be extracted already exist, the tool will exit without creating any yang modules

* If there are syntactic errors such as a yang module statement nested in a yang module, the tool will exit without creating any yang modules

## Testing

xym has a simple set of tests exercising a subset of functionality. Woth xym installed, these may be invoked while in the test subdirectory thus:

```
$ cd test
$ python -m unittest test
```

Expected output is:

```
$ python -m unittest xym
ERROR: 'test-file.txt', Line 21 - Yang module 'ex-error' with no <CODE BEGINS> and not starting with 'example-'
ERROR: 'test-file.txt', Line 47 - Yang module 'example-error' with <CODE BEGINS> and starting with 'example-'
.ERROR: 'test-file.txt', Line 21 - Yang module 'ex-error' with no <CODE BEGINS> and not starting with 'example-'
ERROR: 'test-file.txt', Line 47 - Yang module 'example-error' with <CODE BEGINS> and starting with 'example-'
.ERROR: 'test-file.txt', Line 21 - Yang module 'ex-error' with no <CODE BEGINS> and not starting with 'example-'
ERROR: 'test-file.txt', Line 47 - Yang module 'example-error' with <CODE BEGINS> and starting with 'example-'
.
----------------------------------------------------------------------
Ran 3 tests in 0.004s

OK
$
```
