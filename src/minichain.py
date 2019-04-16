import os
import json

class minichain:
    """
        block header format is ""
        version, prev_block, merkle_root, target, nonce
    """
    def __init__(self, target):
        self.DIR = './blocks'
        if not os.path.isdir(self.DIR):
            os.makedirs(self.DIR,mode=0o777)
        self.target = target
        # genesis block is generated by nodes
        self.index = -1
        self.current_hash = ''
        self.prev_hash = '0'*64
        self.merkle_root = '0000000000000000000000000000000000000000000000000000000000000000'
        self.version = '00000001'
        self.nonce = '00000000'
    # for add the blocks which do not exist in db
    # not for 
    def store_block(self,block,index):
        file_name = self.DIR + '/' + str(index) + '.json' 
        with open(file_name, 'w+') as f:
            f.write(json.dumps(block))
            f.flush()
        f.close()
        return True
    # for insert the latest block
    def insertBlock(self,block_header, block_hash, index):
        try:
            self.index = index
            self.current_hash = block_hash
            # construct block header
            self.version = block_header[0:8]
            self.prev_hash = block_header[8:72]
            self.merkle_root = block_header[72:136]
            self.target = block_header[136:200]
            self.nonce = block_header[200:208]
            block = {
                    "block_header" : {
                        "version" : self.version,
                        "prev_hash" : self.prev_hash,
                        "merkle_root" : self.merkle_root,
                        "target" : self.target,
                                     "nonce" : self.nonce,
                        },
                    "block_hash" : self.current_hash
                    }
            if not self.valid_block(prev_hash):
                return False
            with open(self.DIR+'/'+str(self.index)+'.json', 'w+') as f:
                f.write(json.dumps(block))
                f.flush()
            f.close()
        except:
            return False
        return True
    def valid_block(self, prev_hash):
        valid = self.getBlockHeader(prev_hash)
        if valid is None:
            return False
        else:
            return True

    def updateBlock(self,block,idx):
        self.version = block['block_header']['version']
        self.prev_hash = block['block_header']['prev_hash']
        self.target = block['block_header']['target'] 
        self.merkle_root = block['block_header']['merkle_root']
        self.current_hash = block['block_hash']
        self.index = idx
    def getBlockHashByIndex(self,index):
        if os.path.isfile(self.DIR + '/' + str(index) + '.json'):
            with open(self.DIR + '/' + str(index) + '.json', 'r') as f:
                block = json.load(f)
                block_hash = block['block_hash']
                return block_hash
        else :
            return None
    def getBlockByIndex(self,index):
        file_name = self.DIR + '/' + str(index) + '.json'
        if os.path.isfile(file_name):
            with open(file_name, 'r') as f:
                block = json.load(f)           
                return json.dumps(block)
        return None
    def getIndex(self):
        return self.index
    def getBlockHeader(self,block_hash):
        idx = 0
        while True:
            search_hash = self.getBlockHashByIndex(idx)
            if block_hash == search_hash:
                print(search_hash)
                block = json.loads(self.getBlockByIndex(idx))
                block_header = block['block_header']
                return json.dumps(block_header)
            elif search_hash is None:
                break
            idx = idx + 1
        return None
    def getBlockIndex(self, block_hash):
        idx = 0
        while True:
            search_hash = self.getBlockHashbyIndex(idx)
            if block_hash == search_hash:
                return idx
            elif search_hash == None:
                break
        return -1
    def getBlockHash(self):
        return self.current_hash
    def getDifficult(self):
        return self.target
    def getPrevHash(self):
        return self.prev_hash
    def getVersion(self):
        return self.version
    def getMerkleRoot(self):
        return self.merkle_root
    def getTarget(self):
        return self.target
