import asn1
from collections import OrderedDict
from cryptography.x509 import oid


def monkeypatch_oid_names():
    oid._OID_NAMES[oid.ExtensionOID.SZOID_CERTIFICATE_TEMPLATE] = (
            'szOIDCertificateTemplate'
            )
    oid._OID_NAMES[oid.ExtensionOID.SZOID_APPLICATION_CERT_POLICIES] = (
            'szOIDApplicationCertPolicies'
            )
    oid._OID_NAMES[oid.ExtensionOID.SMIME_CAPABILITIES] = (
            'smimeCapabilities'
            )
    oid._OID_NAMES[oid.ExtensionOID.PRECERT_SIGNED_CERTIFICATE_TIMESTAMPS] = (
            'signedCertificateTimestampList'
            )


def monkeypatch_extension_oids():
    oid.ExtensionOID.SZOID_CERTIFICATE_TEMPLATE = (
            oid.ObjectIdentifier("1.3.6.1.4.1.311.21.7")
            )
    oid.ExtensionOID.SZOID_APPLICATION_CERT_POLICIES = (
            oid.ObjectIdentifier("1.3.6.1.4.1.311.21.10")
            )
    oid.ExtensionOID.SMIME_CAPABILITIES = (
            oid.ObjectIdentifier("1.2.840.113549.1.9.15")
            )


def is_sequence(tag):
    return tag.nr == 16 and tag.typ == 32 and tag.cls == 0


def sequence_decoder_init(der):
    decoder = asn1.Decoder()
    decoder.start(der)
    tag, value = decoder.read()
    if not is_sequence(tag):
        return None, None
    return decoder, value


def decode_smime_capabilities(der):
    (decoder, sequence) = sequence_decoder_init(der)
    if not decoder:
        return der.hex()

    decoder.start(sequence)
    capability_derlist = []
    res = {'capabilities': []}
    while True:
        try:
            tag, value = decoder.read()
            # each capability is itself a sequence
            capability_derlist.append(value)
        except TypeError:
            for capder in capability_derlist:
                decoder.start(capder)
                capability = OrderedDict()
                tag, value = decoder.read()
                capability['capability_id'] = value
                parameters = []
                while True:
                    try:
                        tag, value = decoder.read()
                        parameters.append(value)
                    except TypeError:
                        if len(parameters) > 0:
                            capability['paramters'] = parameters
                        res['capabilities'].append(capability)
                        break

            return res


def decode_szoid_certificate_template(der):
    (decoder, sequence) = sequence_decoder_init(der)
    if not decoder:
        return {"hex": der.hex()}

    decoder.start(sequence)
    res = OrderedDict()

    try:
        tag, value = decoder.read()
        res['template_id'] = value

        tag, value = decoder.read()
        res['major_version'] = value

        tag, value = decoder.read()
        res['minor_version'] = value

    except TypeError:
        return {"hex": der.hex()}

    return res
