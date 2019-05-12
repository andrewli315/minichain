from ecdsa import SigningKey,VerifyingKey,SECP256k1
import hashlib
import binascii

def main():
    sk = SigningKey.generate(curve=SECP256k1)
    pk = sk.get_verifying_key()
    hex_pk = binascii.hexlify(pk.to_string())
    hex_sk = binascii.hexlify(sk.to_string())
    print("pk : " + str(hex_pk,'ascii'))
    print("sk : " + str(hex_sk,'ascii'))

if __name__ == '__main__':
    main()
