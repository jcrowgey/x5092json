from __future__ import absolute_import
import argparse
from base64 import b64encode
from collections import OrderedDict
import select
import sys

from OpenSSL import crypto
import cryptography
from cryptography import x509
from cryptography.x509.name import RelativeDistinguishedName
from cryptography.x509.general_name import GeneralName
from cryptography.hazmat import primitives
from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import ExtensionOID as eoid

import json

from x5092json import more_oids
from x5092json import name_patches
from x5092json import extension_patches
from x5092json import asn1_decode_patches

from ipaddress import IPv4Address, IPv6Address, IPv4Network, IPv6Network

more_oids.monkeypatch_extension_oids()
more_oids.monkeypatch_oid_names()
name_patches.patch_all()
extension_patches.patch_all()
asn1_decode_patches.patch_all()

DEFAULT_BACKEND = cryptography.hazmat.backends.default_backend()
READERS = {'PEM': lambda data: x509.load_pem_x509_certificate(data,
                                                              DEFAULT_BACKEND),
           'DER': lambda data: x509.load_der_x509_certificate(data,
                                                              DEFAULT_BACKEND)}
KEY_USAGE_PROPERTIES = ['content_commitment', 'crl_sign', 'data_encipherment',
                        'decipher_only', 'digital_signature', 'encipher_only',
                        'key_agreement', 'key_cert_sign', 'key_encipherment']
SIGNED_CERT_TIMESTAMP_PROPERTIES = ['version', 'log_id', 'timestamp',
                                    'entry_type']


# Extension formatting functions
def get_crl_number(extension):
    res = {'crl_number': extension.crl_number}
    return res


def get_authority_key_identifier(extension):
    res = OrderedDict()
    if extension.authority_cert_issuer:
        res['authority_cert_issuer'] = []
        for name in extension.authority_cert_issuer:
            if isinstance(name, RelativeDistinguishedName):
                res['authority_cert_issuer'].append(get_name(name.value))
            elif isinstance(name, GeneralName):
                res['authority_cert_issuer'].append(get_general_name(name))
            elif isinstance(name, str):
                res['authority_cert_issuer'].append(name)
            else:
                res['authority_cert_issuer'].append(name.value.hex())
    if extension.authority_cert_serial_number:
        res['authority_cert_serial_number'] = \
                str(extension.authority_cert_serial_number)
    if extension.key_identifier:
        # XXX: If we don't have this, what are we doing here?
        res['key_identifier'] = extension.key_identifier.hex()
    return res


def get_subject_key_identifier(extension):
    res = {'digest': extension.digest.hex()}
    return res


def get_authority_information_access(extension):
    res = {'descriptions': [get_access_description(description)
                            for description in extension._descriptions]}
    return res


def get_access_description(description):
    res = OrderedDict([('access_method', get_oid(description.access_method)),
                       ('access_location',
                        get_general_name(description.access_location))])
    return res


def get_basic_constraints(extension):
    res = {'ca': extension.ca}
    if extension.path_length:
        res['path_length'] = extension.path_length
    return res


def get_delta_crl_indicator(extension):
    # TODO: I think this is actually a CRL extension, not x509.  Verify this.
    res = {'crl_number': extension.crl_number}
    return res


def get_crl_distribution_points(extension):
    res = {'distribution_points': [get_distribution_point(point)
                                   for point in extension]}
    return res


def get_freshest_crl(extension):
    res = {'distribution_points': [get_distribution_point(point)
                                   for point in extension]}
    return res


def get_policy_constraints(extension):
    res = {}
    if extension.require_explicit_policy:
        res['require_explicit_policy'] = extension.require_explicit_policy
    if extension.inhibit_policy_mapping:
        res['inhibit_policy_mapping'] = extension.inhibit_policy_mapping
    return res


def get_certificate_policies(extension):
    return {'policies': [get_policy_information(policy)
                         for policy in extension]}


def get_extended_key_usage(extension):
    return [get_oid(usage) for usage in extension]


def get_ocsp_no_check(extension):
    return str(extension)


def get_tls_feature(extension):
    return {'features': [get_tls_feature_type(feature)
                         for feature in extension]}


def get_tls_feature_type(extension):
    return str(extension)
    # if 'status_request' in extension:
    #     return {'status_request': extension.status_request}
    # elif 'status_request_v2' in extension:
    #     return {'status_request_v2': extension.status_request}


def get_inhibit_any_policy(extension):
    return {"skip_certs": extension.skip_certs}


def get_key_usage(extension):
    res = OrderedDict()
    for prop in KEY_USAGE_PROPERTIES:
        try:
            value = getattr(extension, prop, None)
            if value:
                res[prop] = value
        except ValueError:
            pass
    return res


def get_name_constraints(extension):
    res = {}
    if extension.permitted_subtrees:
        res['permitted_subtrees'] = [get_general_name(name)
                                     for name in extension.permitted_subtrees]
    if extension.excluded_subtrees:
        res['excluded_subtrees'] = [get_general_name(name)
                                    for name in extension.excluded_subtrees]
    return res


def get_subject_alternative_name(extension):
    return [get_general_name(name) for name in extension]


def get_issuer_alternative_name(extension):
    return [get_general_name(name) for name in extension]


def get_certificate_issuer(extension):
    return str(extension)


def get_crl_reason(extension):
    return str(extension)


def get_invalidity_date(extension):
    return str(extension)


def get_precert_signed_timestamps(extension):
    return [get_signed_certificate_timestamp(timestamp)
            for timestamp in extension]


def get_unrecognized_extension(extension):
    return str(extension)


def get_szoid_application_cert_policies(extension):
    # noqa: E501
    # https://support.microsoft.com/en-us/help/287547/object-ids-associated-with-microsoft-cryptography
    # According to that ^^^, this funky thing is supposed to have the same
    # encoding as a PolicyIdentifier, but I can't seem to coerce the backend
    # into parsing the extension for me
    return {"hex": extension.value.hex()}


def get_szoid_certificate_template(extension):
    # TODO: https://msdn.microsoft.com/en-us/library/cc250012.aspx
    # noqa: E501
    # https://support.microsoft.com/en-us/help/287547/object-ids-associated-with-microsoft-cryptography
    return more_oids.decode_szoid_certificate_template(extension.value)


def get_smime_capabilities(extension):
    return more_oids.decode_smime_capabilities(extension.value)


def get_unknown_oid(extension):
    return {"hex": extension.value.hex()}
# End extension formatting functions


EXTENSION_FORMAT_MAPPING = \
        {eoid.CRL_NUMBER: get_crl_number,
         eoid.AUTHORITY_KEY_IDENTIFIER: get_authority_key_identifier,
         eoid.SUBJECT_KEY_IDENTIFIER: get_subject_key_identifier,
         eoid.AUTHORITY_INFORMATION_ACCESS: get_authority_information_access,
         eoid.BASIC_CONSTRAINTS: get_basic_constraints,
         eoid.DELTA_CRL_INDICATOR: get_delta_crl_indicator,
         eoid.CRL_DISTRIBUTION_POINTS: get_crl_distribution_points,
         eoid.FRESHEST_CRL: get_freshest_crl,
         eoid.POLICY_CONSTRAINTS: get_policy_constraints,
         eoid.CERTIFICATE_POLICIES: get_certificate_policies,
         eoid.EXTENDED_KEY_USAGE: get_extended_key_usage,
         eoid.OCSP_NO_CHECK: get_ocsp_no_check,
         eoid.TLS_FEATURE: get_tls_feature,
         eoid.INHIBIT_ANY_POLICY: get_inhibit_any_policy,
         eoid.KEY_USAGE: get_key_usage,
         eoid.NAME_CONSTRAINTS: get_name_constraints,
         eoid.SUBJECT_ALTERNATIVE_NAME: get_subject_alternative_name,
         eoid.ISSUER_ALTERNATIVE_NAME: get_issuer_alternative_name,
         eoid.PRECERT_SIGNED_CERTIFICATE_TIMESTAMPS:
             get_precert_signed_timestamps,
         eoid.SZOID_CERTIFICATE_TEMPLATE: get_szoid_certificate_template,
         eoid.SZOID_APPLICATION_CERT_POLICIES:
             get_szoid_application_cert_policies,
         eoid.SMIME_CAPABILITIES: get_smime_capabilities,
         'UNKNOWN_OID': get_unknown_oid}


def get_user_notice(notice):
    res = OrderedDict()
    res['type'] = 'user_notice'
    if notice.notice_reference:
        res['notice_reference'] = notice.notice_reference
    if notice.explicit_text:
        res['explict_text'] = notice.explicit_text
    return res


def get_policy_qualifier(qualifier):
    if isinstance(qualifier, cryptography.x509.extensions.UserNotice):
        get_user_notice(qualifier)
    else:
        return qualifier


def get_signed_certificate_timestamp(timestamp):
    res = OrderedDict()
    for prop in SIGNED_CERT_TIMESTAMP_PROPERTIES:
        value = getattr(timestamp, prop, None)
        if value:
            if prop == 'log_id':
                value = value.hex()
            res[prop] = str(value)
    return res


def get_general_name(name):
    res = OrderedDict()
    res['type'] = str(name.__class__.__name__)  # XXX: Ugh, really!?
    valuetag = res['type'].lower() + '_value'
    if res['type'] == 'DirectoryName':
        res[valuetag] = get_name(name.value)
    elif res['type'] == 'RegisteredID':
        res[valuetag] = get_oid(name.value)
    else:
        if isinstance(name.value, bytes):
            res[valuetag] = name.value.hex()
        elif isinstance(name.value, (IPv4Address, IPv6Address, IPv4Network,
                                     IPv6Network)):
            # Note: specifying a network here isn't valid (see output of
            # openssl x509 tool)
            res[valuetag] = str(name.value)
        else:
            try:
                res[valuetag] = name.value
            except UnicodeDecodeError:
                res[valuetag] = name.value.hex()
    return res


def get_policy_information(policy_information):
    res = {'policy_identifier': get_oid(policy_information.policy_identifier)}
    if policy_information.policy_qualifiers:
        res['policy_qualifiers'] = \
                [get_policy_qualifier(q)
                 for q in policy_information.policy_qualifiers]
    return res


def get_distribution_point(point):
    point_name = point.full_name if point.full_name else point.relative_name
    res = {'name': [get_general_name(name) for name in point_name]}
    if point.crl_issuer:
        res['crl_issuer'] = [get_name(name.value)
                             for name in point.crl_issuer],
    if point.reasons:
        res['reasons'] = [str(reason) for reason in point.reasons]
    return res


def get_subject_public_key_info(certificate):
    try:
        pubkey = certificate.public_key()
    except ValueError:
        # Unknown type
        # TODO: GOST public key types
        res = OrderedDict()
        res['error'] = "Unknown public key type"

        return res

    # Unfortunately, the cryptography library doesn't expose the actual OID
    # here
    if isinstance(pubkey, primitives.asymmetric.rsa.RSAPublicKey):
        pubkey_algostr = 'rsaEncryption'
    elif isinstance(pubkey, primitives.asymmetric.dsa.DSAPublicKey):
        pubkey_algostr = 'dsaEncryption'
    elif isinstance(pubkey, primitives.asymmetric.ec.EllipticCurvePublicKey):
        pubkey_algostr = 'ecdsaEncryption'

    res = OrderedDict()
    res['algorithm'] = pubkey_algostr
    res['key_size'] = pubkey.key_size
    # NOTE: I think that the modulus/exponent is nicer for RSA, DSA type keys
    # We could branch here and print modulus and exponent for these types, and
    # then x, y, curve name for ecdsa There are some potentially awkward edge
    # cases in ECDSA, (compressed vs uncomporessed, and cetera) So, base64 SPKI
    # is what I'm proposing for the moment.
    #
    #    For RSA:
    #        numbers = pubkey.public_numbers()
    #        res['modulus'] = numbers.n
    #        res['exponent'] = numbers.e
    SPKI = serialization.PublicFormat.SubjectPublicKeyInfo
    res['key'] = b64encode(pubkey.public_bytes(serialization.Encoding.DER,
                                               SPKI)).decode('ascii')
    return res


def get_oid(oid):
    return {'dotted_string': oid._dotted_string,
            'name': oid._name}


def get_name(name):
    res = []
    for attribute in name:
        attr = {}
        attr['oid'] = get_oid(attribute.oid)
        attr['value'] = attribute.value
        res.append(attr)
    return res


def get_extensions(extensions):
    res = []
    for extension in extensions:
        ext = OrderedDict()
        ext['oid'] = get_oid(extension.oid)
        ext['critical'] = extension.critical

        # for OCSP_NO_CHECK, the value is supposed to be null
        if extension.oid != eoid.OCSP_NO_CHECK:
            # XXX: We end up using Unrecognized Extension for things which
            # aren't necessarily unrecognized but just malformed (ie, weren't
            # successfully decoded)
            try:
                ext['value'] = \
                    EXTENSION_FORMAT_MAPPING[extension.oid](extension.value)
            except Exception:
                ext['value'] = \
                    EXTENSION_FORMAT_MAPPING['UNKNOWN_OID'](extension.value)

        res.append(ext)

    return res


def get_namestr(x509name):
    bio = crypto._new_mem_buf()
    print_result = crypto._lib.X509_NAME_print_ex(bio, x509name._name, 0,
                                                  crypto._lib.XN_FLAG_RFC2253)
    assert print_result >= 0
    return crypto._native(crypto._bio_to_string(bio))


# Extraction functions
def set_version(certificate, data):
    # NOTE: This field is zero-indexed: 0 -- 2, corresponding to certificate
    # versions 1, 2 and 3.  I thought this *might' be made slightly clearer by
    # recording a hex string.  Another option: data['version'] =
    # certificate.version.value + 1
    try:
        # for human consumption
        data['version'] = str(certificate.version.value + 1)
    except x509.base.InvalidVersion:
        data['version'] = \
            hex(DEFAULT_BACKEND._lib.X509_get_version(certificate._x509))


def set_serial_number(certificate, data):
    data['serial_number'] = str(certificate.serial_number)


def set_sig_algo(certificate, data):
    data['signature_algorithm'] = certificate.signature_algorithm_oid._name


def set_issuer_str(crypto_cert, data):
    data['issuer_str'] = get_namestr(crypto_cert.get_issuer())


def set_issuer(certificate, data):
    data['issuer'] = get_name(certificate.issuer)


def set_validity(certificate, data):
    res = OrderedDict()

    try:
        nb = certificate.not_valid_before.isoformat()
        res['not_before'] = nb
    except ValueError:
        nb_comment = 'error decoding not_valid_before'
        res['nb_error'] = nb_comment

    try:
        na = certificate.not_valid_after.isoformat()
        res['not_after'] = na
    except ValueError:
        res['na_error'] = 'error decoding not_valid_after'

    data['validity'] = res


def set_subject_str(crypto_cert, data):
    data['subject_str'] = get_namestr(crypto_cert.get_subject())


def set_subject(certificate, data):
    data['subject'] = get_name(certificate.subject)


def set_subject_public_key_info(certificate, data):
    data['subject_public_key_info'] = get_subject_public_key_info(certificate)


def set_name_uids(certificate, data):
    # Not Implemented in PyOpenSSL cffi:
    # void X509_get0_uids(const X509 *x, const ASN1_BIT_STRING **piuid,
    #                     const ASN1_BIT_STRING **psuid)
    return


def set_extensions(certificate, data):
    data['extensions'] = get_extensions(certificate.extensions)


# Main control flow functions
def parse(certificate):
    openssl_cert = crypto.X509.from_cryptography(certificate)
    cert_data = OrderedDict()
    set_version(certificate, cert_data)
    set_serial_number(certificate, cert_data)
    set_sig_algo(certificate, cert_data)
    set_issuer_str(openssl_cert, cert_data)
    set_issuer(certificate, cert_data)
    set_validity(certificate, cert_data)
    set_subject_str(openssl_cert, cert_data)
    set_subject(certificate, cert_data)
    set_subject_public_key_info(certificate, cert_data)
    set_name_uids(certificate, cert_data)
    set_extensions(certificate, cert_data)
    return cert_data


def load_certificate(infile, loadfunction=READERS['PEM']):
    if select.select([infile, ], [], [], 0.0)[0]:
        return loadfunction(infile.read())
    else:
        raise IOError


def get_parser():
    parser = argparse.ArgumentParser('Parse an x509 certificate, output JSON')
    parser.add_argument('--inform', choices=['DER', 'PEM'], default='PEM')
    parser.add_argument('--in', type=argparse.FileType(mode='rb'),
                        default=sys.stdin.buffer.raw)
    parser.add_argument('--out', type=argparse.FileType(mode='w'),
                        default=sys.stdout)
    return parser


def main():
    parser = get_parser()
    args = parser.parse_args()
    try:
        certificate = load_certificate(getattr(args, 'in'),
                                       READERS[args.inform])
    except IOError:
        parser.print_usage()
        sys.exit(1)

    args.out.write(json.dumps(parse(certificate), ensure_ascii=False))


if __name__ == '__main__':
    main()
