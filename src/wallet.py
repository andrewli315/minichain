from CryptoUtil import CryptoUtil
import json
import os


class wallet:
    def __init__(self, public_key, private_key):
        # public key is account address
        self.crypto_util = CryptoUtil(public_key, private_key)        
        self.priv_key = private_key
        self.address = public_key
    # use myself sign the transaction from rpc client
    def checkTxSig(self, tx):
        ret = self.crypto_util.verify(tx.getPubKey(), tx.getSig().encode('utf-8'), tx.getSignData())
        return ret

    def sign(self, tx):
        sig = self.crypto_util.sign(tx.getSignData())
        return sig

    def getPrivateKey(self):
        return self.priv_key
    def getPubKey(self):
        return self.address
