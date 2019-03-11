x5092json
=========
[![Build Status](https://travis-ci.org/jcrowgey/gcalcli.svg?branch=master)](https://travis-ci.org/jcrowgey/x5092json)

Provides a parser and JSON serializer for x509 certificates.

This tool can be used to creating a large database of analyzed
certificates.  Provides a command-line tool as well as an importable
module.  Over 400 Million certificates parsed so far.

Motivation
----------

PyCA-Cryptography (https://github.com/pyca/cryptography) provides a
full set of cryptographic operations for Python programmers, but the
focus of that library is on safety and correctness.  For that reason,
many certificates which one finds "in the wild" are not intializable
as cryptography objects out-of-the-box.  The x5092json package takes
the safety belts off of cyrptography to provide a parser which is
robust to the nonsense which one finds when processing the X509
certificates deployed in the wilds of the Internet.


Installation
------------

Requires Python3.  Tested against Python3.5, 3.6, 3.7.  May work
against earlier Py3Ks.  Because this package relies on pyOpenSSL,
which relies on libssl C bindings, your system will need to be able to
build a wheel.  That, in turn, may require such header files as
`<openssl/opensslv.h>` and `<pyconfig.h>`.  See your distribution's
package manager for these dependencies (or, in the future, I may be
able to push out a pre-compiled package for some systems)---file an
issue if you are interested in this.

From PyPI:

```shell
$ pip3 install x5092json
```

From source :

```shell
$ git clone https://github.com/jcrowgey/x5092json
```


Usage
-----

Can be used as a command line tool:

```shell
$ cat mycert.pem | x5092json
```

For example, the above invocation reads a PEM formatted x509
Certificate from STDIN by default, the JSON document is printed on
STDOUT.

Can also be imported as a module within a python program.

```python
from x5092json import x509parser

# load a pem file from the filesystem
f = open('mycert.pem', mode='rb')
cert = x509parser.load_certificate(f)
x509parser.parse(cert)
```

See the manual for more usage examples and options.


Author
------

Joshua Crowgey
