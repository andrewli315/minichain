

class minichain:
    """
        block header format is ""
        version, prev_block, merkle_root, target, nonce
    """
    def __init__(self, target):
        self.target = target
        self.index = 0
        self.recent_block_hash = ''
        self.prev_hash = '0'*64
        #self.transaction = '000000000000'
        self.merkleroot = '0000000000000000000000000000000000000000000000000000000000000000'
        self.version = '00000001'

    def store_block(self,block,index):
        return block
    def insertBlock(self,index, prev_hash, current_hash, block_data):
        json_str = {
                'index' : index,
                'prev_hash': prev_hash
                }
        return True
    def getBlockByIndex(self,index):
        return str(index)

    def getBlockByHash(self,current_hash):
        return 'null'
    def getDifficult(self):
        return self.target
    def getPrevHash(self):
        return self.prev_hash
    def getVersion(self):
        return self.version
    def getMerkleRoot(self):
        return self.merkleroot
    def getTarget(self):
        return self.target
