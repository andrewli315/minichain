import json
import os
class   transaction:
    def __init__(self, fee, nonce,pubkey,sig,to, value):
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

    def toJsonStr(self)
        ret = {"fee" : self.fee ,
               "nonce": self.nonce,
               "sender_pub_key":self.sender_pubkey,
               "signature" : self.signature,
               "to" : self.to,
               "value" : self.value
                }
        return json.dumps(ret)

        
