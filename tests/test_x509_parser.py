import json
import os
from x5092json import x509parser
from base64 import b64decode
from collections import OrderedDict
import pytest

TEST_DIR = os.path.abspath(os.path.dirname(__file__))
test_data = json.load(
    open(os.path.join(TEST_DIR, "test_data.json")),
    object_pairs_hook=OrderedDict,
)


@pytest.mark.parametrize("test_name", test_data.keys())
def test_run(test_name):
    test_item = test_data[test_name]
    certificate = x509parser.READERS["DER"](b64decode(test_item["raw"]))
    cert_data = x509parser.parse(certificate)
    assert cert_data == test_item["parsed"]


def test_load_files():
    pem_file = open(os.path.join(TEST_DIR, "test_cert.pem"), mode="rb")
    certificate = x509parser.load_certificate(pem_file)
    cert_data = x509parser.parse(certificate)
    assert cert_data

    der_file = open(os.path.join(TEST_DIR, "test_cert.der"), mode="rb")
    certificate = x509parser.load_certificate(
        der_file, x509parser.READERS["DER"]
    )
    cert_data = x509parser.parse(certificate)
    assert cert_data
