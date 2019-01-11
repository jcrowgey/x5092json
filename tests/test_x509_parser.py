import json
from x5092json import x509parser
from base64 import b64decode
from collections import OrderedDict
import pytest

test_data = json.load(open('tests/test_data.json'),
                      object_pairs_hook=OrderedDict)


@pytest.mark.parametrize('test_name', test_data.keys())
def test_run(test_name):
    test_item = test_data[test_name]
    certificate = x509parser.READERS['DER'](b64decode(test_item['raw']))
    cert_data = x509parser.parse(certificate)
    assert cert_data == test_item['parsed']
