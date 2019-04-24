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

class node:
    def __init__(self, p2p_port, user_port, neighbors, minichain):
        self.mutex = threading.Lock()
        self.DIR = './blocks'
        self.p2p_port = p2p_port
        self.user_port = user_port
        self.neighbors = neighbors
        self.minichain = minichain
        self.getHeaderFlag = False
        self.prev_hash = '0'*64
        self.index = -1
    def pauseMining(self,flag):
        self.getHeaderFlag = flag

    def RespondTemplate(self, error, result):
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

    def block_is_valid(self, block_hash, block_header):
        h = hashlib.sha256(block_header.encode('utf-8')).hexdigest()
        if h == block_hash:
            return True
        else:
            return False   
    """
        using proof of work as the consensus algorithm
        h = sha256()
        input = 
            version + prev_hash + merkle_root + target + nonce
        result = sha256(input)
    """
    def mining(self):
        print('[MINING]')
        diff = self.minichain.getDifficult()
        version = self.minichain.getVersion()
        self.prev_hash = self.minichain.getPrevHash()
        merkle_root = self.minichain.getMerkleRoot()
        target = self.minichain.getTarget()
        while True:
            if self.getHeaderFlag:
                self.prev_hash = self.minichain.getBlockHash()
                continue                                    
            rand_num = hex(random.randint(0,4294967295))[2:]
            # using rand to calculate nonce
            nonce = '0'*(8-len(rand_num)) + rand_num            
            block_header = version + self.prev_hash + merkle_root + target + nonce
            recent_hash = hashlib.sha256((block_header.encode('utf-8'))).hexdigest()
            # using mutex to avoid race condition            
            if self.checkHash(recent_hash):                      
                with self.mutex:
                    self.index = self.index + 1
                    self.minichain.insertBlock(block_header, recent_hash,self.index)
                    self.sendHeader(block_header, recent_hash, self.minichain.getIndex())
                    self.prev_hash = recent_hash            

    def checkHash(self,recent_hash):
        diff = str(self.minichain.getTarget()).index('1')
        prefix = recent_hash[:diff]
        if prefix == '0'*diff:
            return True
        else:
            return False
    
    def sendHeader(self,block_header,block_hash, height):
        payload = {
                "method" : "sendHeader",
                "data" : {
                    "block_hash" : block_hash,
                    "block_header" : block_header,
                    "block_height" : height
                    }
                }
        print("[SEND] " + json.dumps(payload))

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
            if len(result) > 0:
                result += data.decode('utf-8')
            else:
                break
        return result

    def process_p2p_request(self, request): 
        method = request['method']
        if method == "getBlocks":
            count = request['data']['hash_count']
            hash_begin = request['data']['hash_begin']
            hash_stop = request['data']['hash_stop']
            result = self.minichain.getBlocks(count,hash_begin, hash_stop)
            print(result)
            if result == None:               
                return self.RespondTemplate(1,None)
            else:                
                return self.RespondTemplate(0,result)
        elif method == "sendHeader":            
            print("[GET]" + json.dumps(request))
            self.pauseMining(True)
            block_index = request['data']['block_height']
            block_hash = request['data']['block_hash']
            block_header = request['data']['block_header']
            prev_hash = block_header[8:72]
            current_hash = self.minichain.getBlockHash()
            if self.block_is_valid(block_hash,block_header) == True:                
                if self.prev_hash == prev_hash:
                    # prevent block overlapping and race condition
                    if self.index == block_index:
                        print("[WARNING] MINE THE SAME BLOCK")
                        self.pauseMining(False)
                        # abort this block
                        return self.RespondTemplate(1,None)
                    # the blockchain is latest in previous block
                    elif self.index == (block_index-1):
                        with self.mutex:
                            self.index = block_index
                            self.minichain.insertBlock(block_header,block_hash, self.index)
                            self.prev_hash = block_hash
                        self.pauseMining(False)
                        return self.RespondTemplate(0,None)
                    else:
                        return self.RespondTemplate(1,None)
                else:
                    if block_index > self.index:                    
                        self.check_fork('0'*64, block_hash, block_index)
                        self.pauseMining(False)
                    else:
                        print("[WARNING] THIS CHAIN IS LONGER")
                        self.pauseMining(False)                    
                        return self.RespondTemplate(1,None)
            else:
                print("[ERROR] INVALID HASH")
                self.pauseMining(False)      
                # hash invalid error
                return self.RespondTemplate(1,None)
            self.pauseMining(False)      
        # unknown method error      
        return self.RespondTemplate(2,None)

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
            print(ret)
<<<<<<< HEAD
            time.sleep(2)
=======
>>>>>>> issue1
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
                    if len(respond) > 4096:
                        for line in range(0, len(respond),4090):
                            client_socket.send(respond[line,line+4090].decode('utf-8'))
                    else:
                        client_socket.send(respond.decode('utf-8'))
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

    def handle_rpc_client(self,client_socket,addr):
        while True:
            try: 
                data = client_socket.recv(4096)
                if len(data) > 0:
                    req = data.decode('utf-8')                    
                    request = json.loads(req)
                    respond = self.process_rpc_request(request)
                    client_socket.send(json.dumps(respond).encode('utf-8'))                    
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
                        print(json.dumps(block))
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

    def start_node(self):
        print("[RUNNING]")
        self.resume()
        # start mining thread
        try:
            mining_thread = threading.Thread(target=self.mining)
            mining_thread.start()
            # start p2p server
            p2p_server_thread = threading.Thread(target=self.listen_p2p)
            p2p_server_thread.start()
            # start rpc server
            rpc_server_thread = threading.Thread(target=self.listen_rpc)
            rpc_server_thread.start()
        except KeyboardInterrupt:
            mining_thread._stop()
            p2p_server_thread._stop()
            rpc_server_thread._stop()
            sys.exit(1)
        
