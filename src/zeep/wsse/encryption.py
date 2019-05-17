"""Functions for WS-Security (WSSE) signature creation and verification.

Heavily based on test examples in https://github.com/mehcode/python-xmlsec as
well as the xmlsec documentation at https://www.aleksey.com/xmlsec/.

Reading the xmldsig, xmlenc, and ws-security standards documents, though
admittedly painful, will likely assist in understanding the code in this
module.

"""
from lxml import etree
from lxml.etree import QName

from zeep import ns
from zeep.exceptions import SignatureVerificationFailed
from zeep.utils import detect_soap_env
from zeep.wsse.utils import ensure_id, get_security_header
from zeep.wsse.signature import Signature, BinarySignature

try:
    import xmlsec
except ImportError:
    xmlsec = None

# This is a subclass of Signature that also encrypts the body of the message
# and just add the signed data to the resulting wsse structure

# Things to read up on:
# what exactly to encrypt; just the body, or also some headers?
#
# other things to try out:
# also add the document first :)
# unencrypted, just signed
# unsigned


# raw sign code, from https://pythonhosted.org/xmlsec/examples.html:
#manager = xmlsec.KeysManager()
#key = xmlsec.Key.from_file('rsacert.pem', xmlsec.constants.KeyDataFormatCertPem, None)
#manager.add_key(key)
#template = etree.parse('enc1-doc.xml').getroot()
#enc_data = xmlsec.template.encrypted_data_create(
#    template, xmlsec.constants.TransformAes128Cbc, type=xmlsec.constants.TypeEncContent, ns="xenc")
#
#xmlsec.template.encrypted_data_ensure_cipher_value(enc_data)
#key_info = xmlsec.template.encrypted_data_ensure_key_info(enc_data, ns="dsig")
#enc_key = xmlsec.template.add_encrypted_key(key_info, xmlsec.Transform.RSA_OAEP)
#xmlsec.template.encrypted_data_ensure_cipher_value(enc_key)
#data = template.find('./Data')
#
## Encryption
#enc_ctx = xmlsec.EncryptionContext(manager)
#enc_ctx.key = xmlsec.Key.generate(xmlsec.constants.KeyDataAes, 128, xmlsec.constants.KeyDataTypeSession)
#enc_datsa = enc_ctx.encrypt_xml(enc_data, data)
#enc_method = xmlsec.tree.find_child(enc_data, xmlsec.constants.NodeEncryptionMethod, xmlsec.constants.EncNs)
#key_info = xmlsec.tree.find_child(enc_data, xmlsec.constants.NodeKeyInfo, xmlsec.constants.DSigNs)
#enc_method = xmlsec.tree.find_node(key_info, xmlsec.constants.NodeEncryptionMethod, xmlsec.constants.EncNs)
#cipher_value = xmlsec.tree.find_node(key_info, xmlsec.constants.NodeCipherValue, xmlsec.constants.EncNs)
#print(etree.tostring(cipher_value))



class Encryption(BinarySignature):
    def __init__(self,
                 public_key_file,
                 private_key_data,
                 cert_data,
                 password=None,
                 encryption_method=None,
                 signature_method=None,
                 digest_method=None):
        super(BinarySignature, self).__init__(private_key_data, cert_data, password, signature_method, digest_method)
        self.public_key_file = public_key_file
        self.encryption_method = encryption_method
        self.manager = xmlsec.KeysManager()
        self.public_key = xmlsec.Key.from_file(public_key_file, xmlsec.constants.KeyDataFormatCertPem, None)
        self.manager.add_key(self.public_key)

    def _encrypt(self, envelope, headers):
        template = get_security_header(envelope)
        # todo: encryption methods
        enc_data = xmlsec.template.encrypted_data_create(
            template, xmlsec.constants.TransformAes128Cbc, type=xmlsec.constants.TypeEncContent, ns="xenc")
        xmlsec.template.encrypted_data_ensure_cipher_value(enc_data)
        key_info = xmlsec.template.encrypted_data_ensure_key_info(enc_data, ns="dsig")
        enc_key = xmlsec.template.add_encrypted_key(key_info, xmlsec.Transform.RSA_OAEP)
        xmlsec.template.encrypted_data_ensure_cipher_value(enc_key)
        data = envelope.find(QName(envelope, "Body"))

        # Encryption
        enc_ctx = xmlsec.EncryptionContext(self.manager)
        enc_ctx.key = xmlsec.Key.generate(xmlsec.constants.KeyDataAes, 128, xmlsec.constants.KeyDataTypeSession)

        # What should be the arguments here? If we pass data, the encrypteddata is added there instead of at the
        # security header...
        enc_data = enc_ctx.encrypt_xml(enc_data, template)
        enc_method = xmlsec.tree.find_child(enc_data, xmlsec.constants.NodeEncryptionMethod, xmlsec.constants.EncNs)
        key_info = xmlsec.tree.find_child(enc_data, xmlsec.constants.NodeKeyInfo, xmlsec.constants.DSigNs)
        enc_method = xmlsec.tree.find_node(key_info, xmlsec.constants.NodeEncryptionMethod, xmlsec.constants.EncNs)
        cipher_value = xmlsec.tree.find_node(key_info, xmlsec.constants.NodeCipherValue, xmlsec.constants.EncNs)

        print("TEMPLATE NOW:")
        print(etree.tostring(envelope.getroottree(), pretty_print=True).decode("utf-8"))
        #print(etree.tostring(cipher_value))

    def apply(self, envelope, headers):
        # TODO: we may need to spread this out; prepare the structure first, then encrypt, then sign
        super(BinarySignature, self).apply(envelope, headers)
        #self._encrypt(envelope, headers)
        return envelope, headers

    def verify(self, envelope):
        #return super(BinarySignature, self).verify(envelope)
        pass
