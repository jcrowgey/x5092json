# import OpenSSL
import ipaddress

from cryptography import x509
from cryptography.hazmat.backends.openssl import decode_asn1
from cryptography.hazmat.backends.openssl.decode_asn1 import (
        _asn1_string_to_bytes,
        _asn1_to_der,
        _decode_x509_name,
        _Integers,
        _obj2txt,
        _X509ExtensionParser
        )
from cryptography.x509.extensions import _TLS_FEATURE_TYPE_TO_ENUM
from cryptography.x509.name import _ASN1_TYPE_TO_ENUM
from cryptography.x509.oid import ExtensionOID


def dump_der(cp, backend):
    data = backend._lib.X509_EXTENSION_get_data(cp)
    backend.openssl_assert(data != backend._ffi.NULL)
    return backend._ffi.buffer(data.data, data.length)[:]


def _patched_decode_x509_name_entry(backend, x509_name_entry):
    obj = backend._lib.X509_NAME_ENTRY_get_object(x509_name_entry)
    backend.openssl_assert(obj != backend._ffi.NULL)
    data = backend._lib.X509_NAME_ENTRY_get_data(x509_name_entry)
    backend.openssl_assert(data != backend._ffi.NULL)
    value = _patched_asn1_string_to_utf8(backend, data)
    oid = _obj2txt(backend, obj)
    try:
        type = _ASN1_TYPE_TO_ENUM[data.type]
    except KeyError:
        type = 'Unsupported ASN1 string type'

    return x509.NameAttribute(x509.ObjectIdentifier(oid), value, type)


def _patched_asn1_string_to_utf8(backend, asn1_string):
    buf = backend._ffi.new("unsigned char **")
    res = backend._lib.ASN1_STRING_to_UTF8(buf, asn1_string)
    if res == -1:
        # "Unsupported ASN1 string type. Type: {0}".format(asn1_string.type)
        # der = backend._lib.ASN1_STRING_data(asn1_string)
        # print(der)
        der = _asn1_string_to_bytes(backend, asn1_string)
        return der.hex()

    backend.openssl_assert(buf[0] != backend._ffi.NULL)
    buf = backend._ffi.gc(
        buf, lambda buffer: backend._lib.OPENSSL_free(buffer[0])
    )

    try:
        return backend._ffi.buffer(buf[0], res)[:].decode('utf8')
    except UnicodeDecodeError:
        return backend._ffi.buffer(buf[0], res)[:].decode('latin1')


def _patched_decode_general_name(backend, gn):
    if gn.type == backend._lib.GEN_DNS:
        # Convert to bytes and then decode to utf8. We don't use
        # asn1_string_to_utf8 here because it doesn't properly convert
        # utf8 from ia5strings.
        name_bytes = _asn1_string_to_bytes(backend, gn.d.dNSName)
        try:
            data = name_bytes.decode("utf8")
        except UnicodeDecodeError:
            data = name_bytes.hex()
        # We don't use the constructor for DNSName so we can bypass validation
        # This allows us to create DNSName objects that have unicode chars
        # when a certificate (against the RFC) contains them.
        return x509.DNSName._init_without_validation(data)
    elif gn.type == backend._lib.GEN_URI:
        # Convert to bytes and then decode to utf8. We don't use
        # asn1_string_to_utf8 here because it doesn't properly convert
        # utf8 from ia5strings.
        name_bytes = _asn1_string_to_bytes(backend,
                                           gn.d.uniformResourceIdentifier)
        try:
            data = name_bytes.decode("utf8")
        except UnicodeDecodeError:
            # TODO: we could try utf16-be
            data = name_bytes.hex()
        # We don't use the constructor for URI so we can bypass validation
        # This allows us to create URI objects that have unicode chars
        # when a certificate (against the RFC) contains them.
        return x509.UniformResourceIdentifier._init_without_validation(data)
    elif gn.type == backend._lib.GEN_RID:
        oid = _obj2txt(backend, gn.d.registeredID)
        return x509.RegisteredID(x509.ObjectIdentifier(oid))
    elif gn.type == backend._lib.GEN_IPADD:
        data = _asn1_string_to_bytes(backend, gn.d.iPAddress)
        data_len = len(data)
        if data_len == 8 or data_len == 32:
            # This is an IPv4 or IPv6 Network and not a single IP. This
            # type of data appears in Name Constraints. Unfortunately,
            # ipaddress doesn't support packed bytes + netmask. Additionally,
            # IPv6Network can only handle CIDR rather than the full 16 byte
            # netmask. To handle this we convert the netmask to integer, then
            # find the first 0 bit, which will be the prefix. If another 1
            # bit is present after that the netmask is invalid.
            base = ipaddress.ip_address(data[:data_len // 2])
            netmask = ipaddress.ip_address(data[data_len // 2:])
            bits = bin(int(netmask))[2:]
            prefix = bits.find('0')
            # If no 0 bits are found it is a /32 or /128
            if prefix == -1:
                prefix = len(bits)

            if "1" in bits[prefix:]:
                raise ValueError("Invalid netmask")

            ip = ipaddress.ip_network(base.exploded + u"/{0}".format(prefix))
        else:
            try:
                ip = ipaddress.ip_address(data)
            except ValueError:
                ip = data

        return x509.IPAddress(ip)
    elif gn.type == backend._lib.GEN_DIRNAME:
        return x509.DirectoryName(
            _decode_x509_name(backend, gn.d.directoryName)
        )
    elif gn.type == backend._lib.GEN_EMAIL:
        # Convert to bytes and then decode to utf8. We don't use
        # asn1_string_to_utf8 here because it doesn't properly convert
        # utf8 from ia5strings.
        data = _asn1_string_to_bytes(backend, gn.d.rfc822Name).decode("utf8")
        # We don't use the constructor for RFC822Name so we can bypass
        # validation. This allows us to create RFC822Name objects that have
        # unicode chars when a certificate (against the RFC) contains them.
        return x509.RFC822Name._init_without_validation(data)
    elif gn.type == backend._lib.GEN_OTHERNAME:
        type_id = _obj2txt(backend, gn.d.otherName.type_id)
        value = _asn1_to_der(backend, gn.d.otherName.value)
        return x509.OtherName(x509.ObjectIdentifier(type_id), value)
    else:
        # x400Address or ediPartyName
        raise x509.UnsupportedGeneralNameType(
            "{0} is not a supported type".format(
                x509._GENERAL_NAMES.get(gn.type, gn.type)
            ),
            gn.type
        )


def _xep_patched_parse(self, backend, x509_obj):
    extensions = []
    seen_oids = set()
    for i in range(self.ext_count(backend, x509_obj)):
        ext = self.get_ext(backend, x509_obj, i)
        backend.openssl_assert(ext != backend._ffi.NULL)
        crit = backend._lib.X509_EXTENSION_get_critical(ext)
        critical = crit == 1
        oid = x509.ObjectIdentifier(
            _obj2txt(backend, backend._lib.X509_EXTENSION_get_object(ext))
        )

        # This OID is only supported in OpenSSL 1.1.0+ but we want
        # to support it in all versions of OpenSSL so we decode it
        # ourselves.
        if oid == ExtensionOID.TLS_FEATURE:
            data = backend._lib.X509_EXTENSION_get_data(ext)
            parsed = _Integers.load(_asn1_string_to_bytes(backend, data))
            value = x509.TLSFeature(
                [_TLS_FEATURE_TYPE_TO_ENUM[x.native] for x in parsed]
            )
            extensions.append(x509.Extension(oid, critical, value))
            seen_oids.add(oid)
            continue

        try:
            handler = self.handlers[oid]
        except KeyError:
            # Dump the DER payload into an UnrecognizedExtension object
            der = dump_der(ext, backend)
            unrecognized = x509.UnrecognizedExtension(oid, der)
            extensions.append(
                x509.Extension(oid, critical, unrecognized)
            )
        else:
            ext_data = backend._lib.X509V3_EXT_d2i(ext)
            if ext_data == backend._ffi.NULL:
                backend._consume_errors()
                der = dump_der(ext, backend)
                unrecognized = x509.UnrecognizedExtension(oid, der)
                extensions.append(x509.Extension(oid, critical, unrecognized))
            else:
                value = handler(backend, ext_data)
                extensions.append(x509.Extension(oid, critical, value))

        seen_oids.add(oid)

    return x509.Extensions(extensions)


def patch_extensionparser():
    _X509ExtensionParser.parse = _xep_patched_parse


def patch_decode_general_name():
    decode_asn1._decode_general_name = _patched_decode_general_name


def patch_asn1_string_to_utf8():
    decode_asn1._asn1_string_to_utf8 = _patched_asn1_string_to_utf8


def patch_decode_x509_name_entry():
    decode_asn1._decode_x509_name_entry = _patched_decode_x509_name_entry


def patch_all():
    patch_extensionparser()
    patch_decode_general_name()
    patch_asn1_string_to_utf8()
    patch_decode_x509_name_entry()
