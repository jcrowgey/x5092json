from cryptography.x509.extensions import (AuthorityKeyIdentifier,
                                          BasicConstraints, KeyUsage,
                                          GeneralNames)
from cryptography.x509.general_name import GeneralName
import six


def _gn_patched__init__(self, general_names):
    general_names = list(general_names)

    if not all(isinstance(x, GeneralName) for x in general_names):
        raise TypeError(
            "Every item in the general_names list must be an "
            "object conforming to the GeneralName interface"
        )

    self._general_names = general_names


def _bc_patched__init__(self, ca, path_length):
    self._ca = ca
    self._path_length = path_length


def _ku_patched__init__(self, digital_signature, content_commitment,
                        key_encipherment, data_encipherment, key_agreement,
                        key_cert_sign, crl_sign, encipher_only, decipher_only):
        self._digital_signature = digital_signature
        self._content_commitment = content_commitment
        self._key_encipherment = key_encipherment
        self._data_encipherment = data_encipherment
        self._key_agreement = key_agreement
        self._key_cert_sign = key_cert_sign
        self._crl_sign = crl_sign
        self._encipher_only = encipher_only
        self._decipher_only = decipher_only


def _aki_patched__init__(self, key_identifier, authority_cert_issuer,
                         authority_cert_serial_number):
        if authority_cert_issuer is not None:
            authority_cert_issuer = list(authority_cert_issuer)
            if not all(
                isinstance(x, GeneralName) for x in authority_cert_issuer
            ):
                raise TypeError(
                    "authority_cert_issuer must be a list of GeneralName "
                    "objects"
                )

        if authority_cert_serial_number is not None and not isinstance(
            authority_cert_serial_number, six.integer_types
        ):
            raise TypeError(
                "authority_cert_serial_number must be an integer"
            )

        self._key_identifier = key_identifier
        self._authority_cert_issuer = authority_cert_issuer
        self._authority_cert_serial_number = authority_cert_serial_number


def patch_basicconstraints():
    BasicConstraints.__init__ = _bc_patched__init__


def patch_keyusage():
    KeyUsage.__init__ = _ku_patched__init__


def patch_authoritykeyidentifier():
    AuthorityKeyIdentifier.__init__ = _aki_patched__init__


def patch_generalnames():
    GeneralNames.__init__ = _gn_patched__init__


def patch_all():
    patch_basicconstraints()
    patch_keyusage()
    patch_authoritykeyidentifier()
    patch_generalnames()
