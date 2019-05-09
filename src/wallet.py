import json
import os


class wallet:
    def __init__(self, private_key, public_key, balance):
        self.private_key = private_key
        self.public_key = public_key
        self.balance = balance

    def update_balance(self):
        self.balance += 1

    def getPrivateKey(self):
        return self.private_key
    def getPublicKey(self):
        return self.public_key
    def getBalance(self):
        return self.balance
