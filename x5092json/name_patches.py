# NameAttribute Class is too stringent
import six
from cryptography.x509.general_name import IPAddress
from cryptography.x509.name import (NameAttribute, _SENTINEL, _ASN1Type,
                                    _NAMEOID_DEFAULT_TYPE)
from cryptography.x509.oid import ObjectIdentifier


def _ipa_patched__init__(self, value):
    self._value = value


def _na_patched__init__(self, oid, value, _type=_SENTINEL):
    if not isinstance(oid, ObjectIdentifier):
        raise TypeError("oid argument must be an ObjectIdentifier instance.")
    if not isinstance(value, six.text_type):
        raise TypeError("value argument must be a text type.")

    # The appropriate ASN1 string type varies by OID and is defined across
    # multiple RFCs including 2459, 3280, and 5280. In general UTF8String
    # is preferred (2459), but 3280 and 5280 specify several OIDs with
    # alternate types. This means when we see the sentinel value we need
    # to look up whether the OID has a non-UTF8 type. If it does, set it
    # to that. Otherwise, UTF8!
    if _type == _SENTINEL:
        _type = _NAMEOID_DEFAULT_TYPE.get(oid, _ASN1Type.UTF8String)
    # if not isinstance(_type, _ASN1Type):
    #     raise TypeError("_type must be from the _ASN1Type enum")
    self._oid = oid
    self._value = value
    self._type = _type


def patch_nameattribute():
    NameAttribute.__init__ = _na_patched__init__


def patch_ipa():
    IPAddress.__init__ = _ipa_patched__init__


def patch_all():
    patch_nameattribute()
    patch_ipa()
