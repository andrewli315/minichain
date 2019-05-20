from ecdsa import SigningKey,VerifyingKey,SECP256k1
import binascii
import hashlib
import base64

class CryptoUtil:
    def __init__(self, public_key, private_key):
        self.private_key = SigningKey.from_string(binascii.unhexlify(private_key),curve = SECP256k1)
        self.public_key = VerifyingKey.from_string(binascii.unhexlify(public_key),curve = SECP256k1)
    def print_key(self):
        print("sk : " + str(binascii.hexlify(self.private_key.to_string())))
        print("pk : " + str(binascii.hexlify(self.public_key.to_string())))
    def sign(self, data):
        signature = binascii.hexlify(self.private_key.sign(data.encode('utf-8'), hashfunc=hashlib.sha256))
        #sig  = self.private_key.sign(data.encode('utf-8'), hashfunc=hashlib.sha256)
        #signature = binascii.hexlify(sig)
        return signature

    def verify(self, public_key, sign, data ):
        ret = False
        try:           
            load_key = VerifyingKey.from_string(binascii.unhexlify(public_key),curve=SECP256k1)
            load_key.verify(binascii.unhexlify(sign), data.encode('utf-8'), hashfunc=hashlib.sha256)
            ret = True
        except:
            ret = False
        finally:
            return ret
