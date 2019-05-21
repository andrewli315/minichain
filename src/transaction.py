import json
import os
import hashlib

class Transaction:
    def __init__(self, tx):
        self.fee = tx['fee']
        self.nonce = tx['nonce']
        self.sender_pub_key = tx['sender_pub_key']
        self.signature = tx['signature'] 
        self.to = tx['to']
        self.value = tx['value']
     
    def storeTxPool(self):
        if not os.path.isdir('./TxPool'):
            os.mkdir('./TxPool')
        with open('./TxPool/'+str(self.signature) +'.tx', 'w+') as tx:
            tx.write(self.toJsonStr())
            tx.flush()
    
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
    def getSig(self):
        return self.signature
    
    # for verifying and signing the tx
    def getSignData(self):
        nonce = hex(self.nonce).rjust(16,'0')
        value = hex(self.value).rjust(16,'0')
        fee = hex(self.fee).rjust(16,'0')
        data = nonce + self.sender_pub_key + self.to + value + fee
        ret = hashlib.sha256(data.encode('utf-8')).hexdigest()
        return ret
    def setSignature(self, sig):
        self.signature = str(sig)
    def toJsonStr(self):
        ret = {
               "fee" : self.fee ,
               "nonce": self.nonce,
               "sender_pub_key":self.sender_pub_key,
               "signature" : self.signature,
               "to" : self.to,
               "value" : self.value
                }
        return json.dumps(ret)
    def toJson(self):
        ret = {
               "fee" : self.fee ,
               "nonce": self.nonce,
               "sender_pub_key":self.sender_pub_key,
               "signature" : self.signature,
               "to" : self.to,
               "value" : self.value
               }
        return ret

        
