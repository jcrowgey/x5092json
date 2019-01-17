x5092json
=========

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
against earlier Py3Ks.

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

For example, the above invocation teads a PEM formatted x509
Certificate from STDIN by default, the JSON document is printed on
STDOUT.

Can also be imported as a module within a python program.

```python
import x5092json

# load a pem file from the filesystem
f = open('mycert.pem')
cert = x5092json.load_certificate(f)
x5092json.parse(cert)
```

See the manual for more usage examples and options.


Author
------

Joshua Crowgey
