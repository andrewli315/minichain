import json
import os


class wallet:
    def __init__(self, public_key, private_key):
        # public key is account address
        self.private_key = private_key
        self.public_key = public_key
        self.balance = 0

    def update_balance(self):        
        self.balance += 1
    def getPrivateKey(self):
        return self.private_key
    def getPublicKey(self):
        return self.public_key
    def getBalance(self):
        return self.balance
