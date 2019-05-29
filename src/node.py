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
        self.alreadyInValidTx = False
        # json object set
        self.txpool = set()


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

    def sendRespond(self, payload):
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
                pass               
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
        tx.setSignature(sig.decode('utf-8'))
        self.pauseMining(True)
        
        with self.mutex:
            ret_str = tx.toJsonStr()
            self.txpool.add(ret_str)
        self.pauseMining(False)
        ret = tx.toJson()
        tx.storeTxPool()
        self.alreadyInValidTx = False
        payload = {
                "method" : "sendTransaction",
                "data" : ret
                }
        print(payload)
        self.sendRespond(payload)
        return self.RespondTemplate(0,None)
    
    def block_is_valid(self,version, prev_hash, tx_hash,beneficiary, target, nonce, txs, block_hash):
        valid_hash = False
        valid = False
        if version != 2:
           return False       
        if target != self.minichain.getTarget():
            print('TARGET ERROR')
            return False
        if tx_hash != self.calculate_tx_hash(txs):
            print('TX HASH ERROR')
            return False
        valid_hash = self.checkHashTarget(block_hash)        
        return valid_hash

            
#check transaction if it appears in previous block,
#the signature is valid and 
#the account's balance is enough for fee and value.

    def check_tx_sig(self, tx):
        transaction = Transaction(tx)
        ret = self.wallet.checkTxSig(transaction)
        if ret == False:
            print('tx sig is invalid')
        return ret
#    this function only for node to 
#    judge if the txpool has valid tx
#    if there is a valid tx then insert it into block
    def check_valid_txs(self, txs): 
        valid_tx = set()
        valid = True
        if txs is None:         
            return None,True
        balance = self.minichain.getAllBalance()
        for tx_str in txs:
            tx = json.loads(tx_str)
            #balance = self.minichain.getBalanceOf(tx['sender_pub_key'])
            fee = tx['fee'] + tx['value']
            if tx['sender_pub_key'] in balance:
                if self.check_tx_sig(tx) and not self.minichain.tx_is_exist(tx['signature']) and balance[tx['sender_pub_key']] >= fee:
                    balance[tx['sender_pub_key']] -= fee
                    if tx['to'] in balance:
                        balance[tx['to']] += tx['value']
                    else:
                        balance[tx['to']] = 0
                        balance[tx['to']] += tx['value']    
                    valid_tx.add(tx_str)
                elif self.check_tx_sig(tx) or self.minichain.tx_is_exist(tx['signature']):
                    valid =  False
            else:
                valid = False
        return valid_tx,valid
    def sigInBlock(self, tx):
        return self.minichain.tx_is_exist(tx.getSig())
    def calculate_tx_hash(self,txs):
        tx_signs = ''
        sigs = {}
        if not txs:
            ret = hashlib.sha256(''.encode('utf-8')).hexdigest()
        else:
            for tx_str in txs:
                tx = json.loads(tx_str)
                sigs[tx['nonce']] = tx['signature']
            for i in sorted(sigs):
                tx_signs += sigs[i]
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

                if self.alreadyInValidTx == False:
                    valid_txs, valid = self.check_valid_txs(self.txpool)
                    tx_hash = self.calculate_tx_hash(valid_txs)
                    self.alreadyInValidTx = True                

                block_header = version + self.prev_hash + tx_hash + target + nonce + self.beneficiary
                recent_hash = hashlib.sha256((block_header.encode('utf-8'))).hexdigest()
                # using mutex to avoid race condition   
                if self.checkHashTarget(recent_hash):                      
                    self.index = self.index + 1
                    self.minichain.insertBlock(self.index, self.prev_hash,
                            tx_hash, self.beneficiary, self.minichain.getTarget(), nonce,
                            valid_txs, recent_hash)
                    
                    #  sendBlock
                    data = self.minichain.getBlockJson(recent_hash)
                    self.sendBlock(self.index, data)
                    self.prev_hash = recent_hash            
                    self.alreadyInValidTx = False
    
    def checkHashTarget(self,recent_hash):
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
        self.sendRespond(payload)        
         
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
            if self.wallet.checkTxSig(tx) and not self.sigInBlock(tx):
                with self.mutex:
                    tx.storeTxPool()
                    self.txpool.add(tx.toJsonStr())
                self.alreadyInValidTx = False
                return self.RespondTemplate(0,None)
            else:
                return self.RespondTemplate(1,None)

        elif method == "sendBlock":
            print("[GET]" + json.dumps(request))
            block = json.loads(request['data'])
            self.pauseMining(True)
            height = request['height']
            version = block['version']
            prev_hash = block['prev_block']
            tx_hash = block['transactions_hash']
            beneficiary = block['beneficiary']
            target = block['target']
            nonce = block['nonce']
            txs = block['transactions']
            
            block_header = ''
            block_header += str(version).rjust(8,'0')
            block_header += prev_hash
            block_header += tx_hash
            block_header += target
            block_header += nonce
            block_header += beneficiary
            block_hash = hashlib.sha256(block_header.encode('utf-8')).hexdigest()

            txs_dict = set()
            self.alreadyInValidTx = False
            for tx in txs:
               txs_dict.add(json.dumps(tx))
            valid_txs, valid = self.check_valid_txs(txs_dict)
            if valid and self.block_is_valid(version, prev_hash, tx_hash, beneficiary, target, nonce, txs_dict,block_hash) == True:
                with self.mutex:
                    if self.index < height:
                        self.index = height
                        self.prev_hash = block_hash
                    self.minichain.insertBlock(height, prev_hash, tx_hash,beneficiary, target, nonce, txs_dict, block_hash)
                    print(self.minichain.getIndex())
                self.pauseMining(False)
                return self.RespondTemplate(0,None)
            elif valid == False:
                self.pauseMining(False)
                return self.RespondTemplate(1,None)
        self.pauseMining(False)
        # unknown method error      
        return self.RespondTemplate(1,None)

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
            print(request)
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


    def start_node(self):
        print("[RUNNING]")       
        try:
            # start p2p server
            p2p_server_thread = threading.Thread(target=self.listen_p2p)
            p2p_server_thread.start()
            # start rpc server
            rpc_server_thread = threading.Thread(target=self.listen_rpc)
            rpc_server_thread.start()

            time.sleep(self.delay)
            # start miner
            if self.is_miner is True:
                mining_thread = threading.Thread(target=self.mining)
                mining_thread.start()          
        except KeyboardInterrupt:
            mining_thread._stop()
            p2p_server_thread._stop()
            rpc_server_thread._stop()
            sys.exit(1)
        
