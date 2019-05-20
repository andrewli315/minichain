import socket
import traceback
import time
import os
import threading
import json
import hashlib
import random
from neighbor import Neighbor
from minichain import minichain
from transaction import Transaction
from wallet import wallet

class node:
    def __init__(self, p2p_port, user_port, neighbors, minichain,beneficiary, wallet,fee, delay, is_miner):
        self.mutex = threading.Lock()
        self.DIR = './blocks'
        self.p2p_port = p2p_port
        self.user_port = user_port
        self.neighbors = neighbors
        self.minichain = minichain
        self.getHeaderFlag = False
        self.prev_hash = '0'*64
        self.index = -1
        self.beneficiary = beneficiary
        self.wallet = wallet
        self.delay = delay
        self.fee = fee
        self.tx_nonce = 0
        self.is_miner = is_miner
        self.block_hash_pool = set()
        # json object set
        self.txpool = set()

    # send tx to target address
    def send2Addr(self, target, amount):
        self.tx_nonce += 1
        data = {
                "nonce" : self.tx_nonce,
                "sender_pub_key" : self.wallet.getPubKey(),
                "to" : target,
                "value" : amount,
                "fee" : self.fee,
                "signature" : ''
                }
        tx = Transaction(data)
        sig = self.wallet.sign(tx)
        tx.setSignature(sig)
        self.pauseMining(True)
        with self.mutex:
            ret_str = tx.toJsonStr()
            self.txpool.add(ret_str)
        self.pauseMining(False)
        ret = tx.toJson()
        tx.storeTxPool()
        # TODO
        # call sendTransaction api
        payload = {
                "method" : "sendTransaction",
                "data" : ret
                }
        for neighbor in self.neighbors:
            client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                client.connect((neighbor.getAddr(), neighbor.getp2pPort()))
                client.send(json.dumps(payload).encode('utf-8'))
                result = client.recv(2048)
                respond = json.loads(result.decode('utf-8'))
                if respond['error'] == 1:
                    print("[ERROR] INTERNAL ERROR")
                client.close()
            except socket.error:
                pass       
        return self.RespondTemplate(0,None)

    def pauseMining(self,flag):
        self.getHeaderFlag = flag

    def RespondTemplate(self, error, result, fmt='result'):
        if fmt == 'result':
            if result == None:
                respond={
                    "error" : error
                }
                return json.dumps(respond)
            else:
                respond = {
                    "error" : error,
                    "result" : result
                }
                return json.dumps(respond)     
        elif fmt == 'balance':
            if result == None:
                respond = {
                    "error" : error
                }
                return json.dumps(respond)
            else:
                respond = {
                    "error" : error,
                    "balance" : result
                }
                return json.dumps(respond)
    def block_is_valid(self,version, prev_hash, tx_hash,beneficiary, target, nonce, txs, block_hash):
        valid_hash = False
        valid_txs = False
        if version != 2:
           return False
        if target != self.minichain.getTarget():
            return False
        if tx_hash != calculate_tx_hash(txs):
            return  False
        if self.checkHash(block_hash):
            valid_hash =  True            
        if self.check_valid_tx(self,txs, tx_hash):
            valid_txs = False
        return (valid_hash and valid_txs )

#check transaction if it appears in previous block,
#the signature is valid and 
#the account's balance is enough for fee and value.

    def check_tx_sig(self, tx):
        transaction = Transaction(tx)
        ret = self.wallet.checkTxSig(transaction)
        return True 
#    this function only for node to 
#    judge if the txpool has valid tx
#    if there is a valid tx then insert it into block
    def check_valid_txs(self): 
        valid_tx = set()
        if not self.txpool:
            return None
        for tx_str in self.txpool:
            tx = json.loads(tx_str)
            balance = self.minichain.getBalanceOf(tx['sender_pub_key'])
            fee = tx['fee'] + tx['value'] 
            if self.check_tx_sig(tx) and not self.minichain.tx_is_exist(tx['signature']) and balance >= fee:
                valid_tx.add(tx_str)
        return valid_tx
    
    def calculate_tx_hash(self,txs):
        tx_signs = ''
        if txs is None:
            ret = hashlib.sha256(''.encode('utf-8')).hexdigest()
        else:
            for tx_str in txs:
                tx = json.loads(tx_str)
                tx_signs += tx['signature']
            ret = hashlib.sha256(tx_signs.encode('utf-8')).hexdigest()
        return ret
    """
        using proof of work as the consensus algorithm
        h = sha256()
        input = 
            version + prev_hash + tx_hash  + target + nonce + beneficiary
        result = sha256(input)
    """
    def mining(self):
        print('[MINING]')
        diff = self.minichain.getDifficult()
        version = str(self.minichain.getVersion()).rjust(8,'0')
        self.prev_hash = self.minichain.getPrevHash()
        tx_hash = self.minichain.getTxHash()
        target = self.minichain.getTarget()
        while True:
            if self.getHeaderFlag:
                self.prev_hash = self.minichain.getBlockHash()
                continue                                                    
            # using rand to calculate nonce
            
            with self.mutex:
                rand_num = hex(random.randint(0,4294967295))[2:]
                nonce = '0'*(8-len(rand_num)) + rand_num
                valid_txs = self.check_valid_txs()                
                tx_hash = self.calculate_tx_hash(valid_txs)
                block_header = version + self.prev_hash + tx_hash + target + nonce + self.beneficiary
                recent_hash = hashlib.sha256((block_header.encode('utf-8'))).hexdigest()
                # using mutex to avoid race condition            
                if self.checkHash(recent_hash):                      
                    self.index = self.index + 1
                    self.minichain.insertBlock(self.index, self.prev_hash,
                            tx_hash, self.beneficiary, self.minichain.getTarget(), nonce,
                            valid_txs, recent_hash)
                    
                    #  sendBlock
                    data = self.minichain.getBlockJson(recent_hash)
                    self.sendBlock(self.index, data)
                    self.prev_hash = recent_hash            
    
    def checkHash(self,recent_hash):
        diff = str(self.minichain.getTarget()).index('1')
        prefix = recent_hash[:diff]
        if prefix == '0'*diff:
            return True
        else:
            return False
    
    def sendBlock(self,height,block ):
        payload = {
                "method" : "sendBlock",
                "height" : height,
                "data" : block
                }
        print("[SEND] " + json.dumps(payload))

        for neighbor in self.neighbors:
            client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                client.connect((neighbor.getAddr(), neighbor.getp2pPort()))
                client.send(json.dumps(payload).encode('utf-8'))
                result = client.recv(2048)
                respond = json.loads(result.decode('utf-8'))
                print(respond)
                if respond['error'] == 1:
                    print("[ERROR] INTERNAL ERROR")
                client.close()
            except socket.error:
                print('test')
                pass       
         
    def getBlocks(self, count, hash_begin, hash_stop,client):
        payload = {
                "method" : "getBlocks",
                "data":{
                    "hash_count" : count,
                    "hash_begin" : hash_begin,
                    "hash_stop"  : hash_stop
                    }
                }
        client.send(json.dumps(payload).encode('utf-8'))
        result =''
        while True:
            data = client.recv(4096)
            result += data.decode('utf-8')
            if len(data) < 4096:
                break
        return result

    def process_p2p_request(self, request): 
        method = request['method']
        print(method)
        if method == "getBlocks":
            count = request['data']['hash_count']
            hash_begin = request['data']['hash_begin']
            hash_stop = request['data']['hash_stop']
            result = self.minichain.getBlocks(count,hash_begin, hash_stop)
            if result == None:               
                return self.RespondTemplate(1,None)
            else:                
                return self.RespondTemplate(0,result)
        elif method == "sendTransaction":
            data = request['data']
            tx = Transaction(data)
            if wallet.checkTxSig(tx):
                tx.storeTxPool()
                self.txpool.add(tx.toJson())

        elif method == "sendBlock":
            print("[GET]" + json.dumps(request))
            block = json.loads(request['data'])
            self.pauseMining(True)
            height = request['height']
            version = block['version']
            prev_hash = block['prev_hash']
            tx_hash = block['transactions_hash']
            beneficiary = block['beneficiary']
            target = block['target']
            nonce = block['nonce']
            txs = block['transactions']
            
            block_header = ''
            block_header += str(version).rjust(8,'0')
            block_header += prev_hash
            block_header += tx_hash
            block_header += beneficiary
            block_header += target
            block_header += nonce
            block_hash = hashlib.sha256(block_header.encode('utf-8')).hexdigest()
            
            if self.block_is_valid(version, prev_hash, tx_hash, beneficiary, target, nonce, txs) == True:
                self.minichain.insertBlock(height, prev_hash, tx_hash,beneficiary, target, nonce, txs)
                if txs is not None:
                    for tx in txs:
                        transaction = Transaction(tx)
                        transaction.storeTxPool()
                        self.txpool.add(tx)
                self.pauseMining(False)
                return self.RespondTemplate(0,None)
            else:
                print("[ERROR] INVALID Block")
                self.pauseMining(False)      
                # hash invalid error
                return self.RespondTemplate(1,None)
            self.pauseMining(False)      
        # unknown method error      
        return self.RespondTemplate(1,None)

    def getMaxFork(self, max_chain):
        idx = 0                
        for item in max_chain['result']:
            m = hashlib.sha256()
            m.update(item.encode('utf-8'))
            h = m.hexdigest()
            recent_hash = h
            with self.mutex:
                self.minichain.insertBlock(item, recent_hash, idx )
            idx = idx + 1
        self.index = idx - 1
        self.prev_hash = recent_hash
    # make sure the fork is the longest 
    def check_fork(self, prev_hash, recent_hash,block_height):
        print("[SYNC FORK]")
        max_length = -1
        # request for each nodes to get the max chain        
        for neighbor in self.neighbors:
            try:
                client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                client.connect((neighbor.getAddr(),neighbor.getp2pPort()))
            except:                
                continue
            ret = self.getBlocks(block_height + 1, prev_hash, recent_hash, client)
            respond = json.loads(ret)
            if respond['result'] is not None:
                chain_length = len(respond['result'])
            else:
                chain_length = -1
            if max_length < chain_length:
                max_length = chain_length
                max_chain = respond 
        # update the max fork        
        self.getMaxFork(max_chain)
        client.close()
        return True

        # handle the p2p client request.
    def handle_p2p_client(self,client_socket,addr):
        while True:
            try:
                data = client_socket.recv(4096)
                if len(data) > 0:
                    req = data.decode('utf-8')                    
                    request = json.loads(req)                    
                    respond = self.process_p2p_request(request)
                    client_socket.send(respond.encode('utf-8'))
                else:
                    break
            except:
                traceback.print_exc()
                break
        client_socket.close()


    def listen_p2p(self):
        print('[Listen for P2P Request on {} {}]'.format('0.0.0.0', self.p2p_port))
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s :
            s.bind(('0.0.0.0', self.p2p_port))
            s.listen(100)
            while True:
                c, addr = s.accept()
                try:
                    threading.Thread(target=self.handle_p2p_client, args=(c,addr)).start()
                except:
                    print("Exception happened")
                    traceback.print_exc()
            s.close()

    def process_rpc_request(self,request):
        method = request['method']                
        if method == "getBlockCount":
            count = self.minichain.getIndex()
            respond = self.RespondTemplate(0,count)
            return respond
        elif method == "getBlockHash":
            index = request['data']['block_height']
            result = self.minichain.getBlockHashByIndex(index)            
            if result is None:
                respond = self.RespondTemplate(1,None)
            else:
                respond = self.RespondTemplate(0,result)
            return respond

        elif method == "getBlockHeader":
            block_hash = request['data']['block_hash']
            result = self.minichain.getBlockHeader(block_hash)            
            if result is None:
                return self.RespondTemplate(1,"null")
            else:     
                return self.RespondTemplate(0,json.loads(result))

        elif method == "getbalance":
            target_address = request['data']['address']
            balance = self.minichain.getBalanceOf(target_address)
            return self.RespondTemplate(0,balance, fmt='balance')
        elif method == "sendtoaddress":
            target_addr = request['data']['address']
            amount = request['data']['amount']
            ret = self.send2Addr(target_addr, amount)
            return ret 

    def handle_rpc_client(self,client_socket,addr):
        while True:
            try: 
                data = client_socket.recv(4096)
                if len(data) > 0:
                    req = data.decode('utf-8')                    
                    request = json.loads(req)
                    respond = self.process_rpc_request(request)
                    client_socket.send(respond.encode('utf-8'))   
                else:
                    break
            except:
                print("client error")
                traceback.print_exc()
                break
        client_socket.close()
    
    def listen_rpc(self):
        print('[Listen for RPC Request on {} {}]'.format( '0.0.0.0',str(self.user_port) ))
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:            
            s.bind(('0.0.0.0', self.user_port))
            # at most 100 clients connection
            s.listen(100)
            while True:
                c, addr = s.accept()
                try:
                    threading.Thread(target=self.handle_rpc_client, args=(c,addr)).start()
                except:
                    print("Exception happened")
                    traceback.print_exc()
            s.close()


#this version would not use this function

    def resume(self):
        if os.path.isdir(self.DIR):
            print("[CHECKING]")
            idx = 0
            file_is_null = False
            while True:
                file_name = self.DIR + '/' + str(idx) + '.json'
                """
                    if last time write file is failed
                    then suppose the corresponded block is failed
                    get the previous block as latest block.
                """ 
                if file_is_null:
                    with open(file_name, 'r') as f:
                        
                        block = json.load(f)
                        self.minichain.updateBlock(block,idx)
                    self.index = idx
                    break
                """
                    check the directory "./blocks" if there are any block files.
                    if there are some files, update the minichain.
                """
                if not os.path.isfile(file_name) and idx > 0 :
                    with open(self.DIR + '/' + str(idx-1) + '.json', 'r') as f:
                        try:
                            print("[UPDATE]")
                            block = json.load(f)
                        except:
                            print("this file is empty")
                            idx = idx - 2
                            file_is_null = True
                            continue
                        print(json.dumps(block))
                        self.minichain.updateBlock(block,idx-1)
                    self.index = idx - 1
                    break                
                #if the genesis file does not exist, skip the checking.                
                if not os.path.isfile(file_name) and idx == 0 :
                    break
                idx = idx + 1
        # check previous tx record



    def start_node(self):
        print("[RUNNING]")
        #self.resume()
        # start mining thread
        
        try:
            # start p2p server
            p2p_server_thread = threading.Thread(target=self.listen_p2p)
            p2p_server_thread.start()
            # start rpc server
            rpc_server_thread = threading.Thread(target=self.listen_rpc)
            rpc_server_thread.start()

            print(self.delay)
            time.sleep(self.delay)
            print('delay finish')
            # start miner
            if self.is_miner is True:
                mining_thread = threading.Thread(target=self.mining)
                mining_thread.start()          


        except KeyboardInterrupt:
            mining_thread._stop()
            p2p_server_thread._stop()
            rpc_server_thread._stop()
            sys.exit(1)
        
