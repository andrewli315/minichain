import json
import os
import hashlib

class Transaction:
    def __init__(self, nonce, pubkey, to, value, fee, signature ):
        self.fee = fee
        self.nonce = nonce
        self.sender_pubkey = pubkey
        self.signature = sig
        self.to = to
        self.value = value
    
    def storeTxPool(self):
        if not os.path.isdir('./TxPool'):
            os.mkdir('./TxPool')
        with open('./TxPool/'+str(self.nonce) +'.tx', 'w+') as tx:
            tx.write(self.toJson())
    def getTo(self):
        return self.to
    def getValue(self):
        return self.value
    def getNonce(self):
        return self.nonce
    def getFee(self):
        return self.fee    
    def getPubKey(self):
        return self.sender_pub_key
    
    # for verifying and signing the tx
    def getData(self):
        nonce = hex(self.nonce).rjust(16,'0')
        value = hex(self.value).rjust(16,'0')
        fee = hex(self.fee).rjust(16,'0')
        data = nonce + self.sender_pub_key + self.to + value + fee
        ret = hashlib.sha256(data.encode('utf-8'))
        return ret
        

    def toJsonStr(self)
        ret = {"fee" : self.fee ,
               "nonce": self.nonce,
               "sender_pub_key":self.sender_pubkey,
               "signature" : self.signature,
               "to" : self.to,
               "value" : self.value
                }
        return json.dumps(ret)

        
