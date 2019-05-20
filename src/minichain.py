import os
import json
import traceback
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
        self.current_hash = '0'*64
        self.beneficiary = ''
        self.prev_hash = '0'*64
        self.tx_hash = '0000000000000000000000000000000000000000000000000000000000000000'        
        self.version = 2
        self.beneficiary = ''
        self.nonce = '00000000'
        self.block_hash_pool = set()

    def tx_is_exist(self, tx_sig):
        height, block_hash = self.findMaxFork()
        ret = False
        for i in range(0, height + 1):
            file_name = self.DIR + '/' + block_hash + '.json'
            with open(file_name,'r') as data:
                block = json.load(data)
            if block['transactions'] is not None:
                for tx in block['transactions']:                   
                    if tx['signature'] == tx_sig:
                        ret = True
                        return ret
            block_hash = block['prev_block']
        return ret
    def findMaxFork(self):
        max_height = -1
        fork_hash = ''
        for block_hash in self.block_hash_pool:
            file_name = self.DIR + '/' + block_hash + '.json'
            with open(file_name, 'r') as data:
                block = json.load(data)
            if max_height < block['height']:
                max_height = block['height']
                fork_hash = block_hash
        return max_height,fork_hash
    """
        when confirmation >= 3, the block could be 
        regarded as credible and immutable.
        Therefore we count the balance only if the 
        confirmation of transaction is >= 3
    """

    def getBalanceOf(self, address):
        height, block_hash = self.findMaxFork()
        balance = 0
        confirmation = 1
        for i in range(0,height+1):
            file_name = self.DIR + '/' + block_hash + '.json'
            with open(file_name,'r') as data:
                block = json.load(data)
            if confirmation >= 3:
                beneficiary = block['beneficiary']
                if beneficiary == address:
                    balance += 1000
                txs = block['transactions']
                if txs is not None:                    
                    for tx in txs:
                        balance += tx['fee']
                        if tx['to'] == address:
                            balance += tx['value']
                        elif tx['sender_pub_key'] == address:
                            balance -= tx['value']
            confirmation += 1
            block_hash = block['prev_block']
        return balance
    # for insert the latest block
    def getBlockJson(self,block_hash):
        file_name = self.DIR + '/' + block_hash + '.json'
        with open(file_name, 'r') as data:
            block = json.load(data)
            ret = {
                    "version" : block['version'],
                    "prev_block" : block['prev_block'],
                    "transactions_hash" : block['transactions_hash'],
                    "beneficiary" : block['beneficiary'],
                    "target" : block['target'],
                    "nonce" : block['nonce'],
                    "transactions": block['transactions']
                    }
            return json.dumps(ret)

    def insertBlock(self, height,prev_hash,tx_hash,beneficiary, target, nonce, txs, block_hash):
        print(block_hash)
        if txs != None:
            valid_txs = []
            for tx in txs:
                valid_txs.append(json.loads(tx))
        else:
            valid_txs = []
        try:
            if self.current_hash == prev_hash and self.index == (height - 1):
                self.index = height
                self.current_hash = block_hash
                # construct block header
                self.prev_hash = prev_hash
                self.tx_hash = tx_hash            
                self.target = target
                self.nonce = nonce
                self.beneficiary = beneficiary                
            block = {
                        "version" : self.version,
                        "height" : height,
                        "prev_block" : prev_hash,
                        "transactions_hash" : tx_hash,
                        "beneficiary" : beneficiary,
                        "target" : target,
                        "nonce" : nonce,
                        "transactions" : valid_txs
                    }
            self.block_hash_pool.add(block_hash)
            print(block)
            file_name = self.DIR + '/' + str(block_hash) + '.json'
            with open(file_name , 'w+') as f:
                f.write(json.dumps(block))
                f.flush()
            f.close()
        except:
            traceback.print_exc()
            print("Except")

    def updateBlock(self,block,idx):
        self.version = block['version']
        self.prev_hash = block['prev_block']
        self.target = block['target'] 
        self.tx_hash = block['transactions_hash']
        self.current_hash = block['block_hash']
        self.nonce = block['nonce']        
        self.index = idx
    
    def getBlockHashByIndex(self,index):
        file_name = self.DIR + '/' + str(index) + '.json'
        if os.path.isfile(file_name):
            with open(file_name, 'r') as f:
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


    def getBlockHeader(self,block_hash):
        idx = 0
        while True:
            search_hash = self.getBlockHashByIndex(idx)
            if block_hash == search_hash:
                block = json.loads(self.getBlockByIndex(idx))
                block_header = block['block_header']
                return json.dumps(block_header)
            elif search_hash is None:
                break
            idx = idx + 1
        return None
    def getBlocks(self, count, hash_begin, hash_stop):        
        idx = self.getBlockIndex(hash_begin)
        begin = idx
        stop = idx + count + 1
        result = []
        for i in range(begin, stop):
            data = self.getBlockByIndex(i)
            if data is None:
                break
            block = json.loads(data)
            block_header = block['block_header']['version'] 
            block_header += block['block_header']['prev_block']
            block_header += block['block_header']['merkle_root'] 
            block_header += block['block_header']['target'] 
            block_header += block['block_header']['nonce']
            result.append(block_header)
        return result

    def getBlockIndex(self, block_hash):
        if block_hash == '0'*64:
            return 0
        idx = 0
        while True:
            search_hash = self.getBlockHashByIndex(idx)
            if block_hash == search_hash:
                return idx
            elif search_hash == None:
                break
        return -1

    def getIndex(self):
        return self.index

    def getBlockHash(self):
        return self.current_hash

    def getDifficult(self):
        return self.target

    def getPrevHash(self):
        return self.prev_hash

    def getVersion(self):
        return self.version

    def getTxHash(self):
        return self.tx_hash

    def getTarget(self):
        return self.target
