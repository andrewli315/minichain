import socket
import traceback
import time
import sys
import os
import threading
from minichain import minichain
import json
import hashlib
import random
from neighbor import Neighbor

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
                        
            m = hashlib.sha256()
            rand_num = hex(random.randint(0,4294967295))[2:]
            nonce = '0'*(8-len(rand_num)) + rand_num
    
            block_header = version + self.prev_hash + merkle_root + target + nonce
            m.update(block_header.encode('utf-8'))
            recent_hash = m.hexdigest()
            # mutex lock for minichain
            if self.checkHash(recent_hash):
                    # insertBlock
                    # sendBlock              
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

        for neighbor in neighbors:
            client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                client.connect((neighbor.getAddr(), neighbor.getp2pPort()))
                client.send(json.dumps(payload).encode('utf-8'))
                result = client.recv(2048)
                #respond = RespondTemplate(0,None)
                #client.send(respond.encode('utf-8'))
                client.close()
            except:
                print("[ERROR] cannot connect to client")
                continue
        

    def getNeighbor(self, addr):
        for neighbor in self.neighbors:
            if addr == neighbor.getAddr():
                return neighbor.getp2pPort()
    
    
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
        result = client.recv(0x7FFFFFFF)
        #respond = self.RespondTemplate(0,None)
        #client.send(respond.encode('utf-8'))
        return result.decode('utf-8')

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

    def process_p2p_request(self, request,addr):
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
        elif method == "sendHeader":            
            print("[GET]")
            self.pauseMining(True)
            block_index = request['data']['block_height']
            block_hash = request['data']['block_hash']
            block_header = request['data']['block_header']
            prev_hash = block_header[8:72]
            current_hash = self.minichain.getBlockHash()            
            if self.prev_hash == prev_hash:
                # the blockchain is latest in previous block
                with self.mutex:
                    self.index = block_index
                    self.minichain.insertBlock(block_header,block_hash, self.index)
                    self.prev_hash = block_hash

            else:
                if block_index > self.index:                    
                    self.check_fork('0'*64, block_hash, block_index, addr)
                    self.pauseMining(False)
                    
                else:
                    print("My chain is longer than him")
                    self.pauseMining(False)                    
                    return self.RespondTemplate(1,None)

            self.pauseMining(False)      
            return self.RespondTemplate(0,None)      
        return self.RespondTemplate(2,None)
    # make sure the fork is the longest 
    def check_fork(self, prev_hash, recent_hash,block_height, addr):
        print("[SYNC FORK]")
        p2p_port = self.getNeighbor(addr)
        try:
            client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client.connect((str(addr), p2p_port))
        except:
            print("EXCEPT")
        print(block_height)        
        ret = self.getBlocks(block_height + 1, prev_hash, recent_hash, client)
        respond = json.loads(ret)
        respond = json.loads(respond)
        idx = 0        
        for item in respond['result']:
            m = hashlib.sha256()
            m.update(item.encode('utf-8'))
            h = m.hexdigest()
            recent_hash = h
            with self.mutex:
                self.minichain.insertBlock(item, recent_hash, idx )
            idx = idx + 1
        self.index = idx 
        print(self.index)
        self.prev_hash = recent_hash
        client.close()
        return True

    def process_rpc_request(self,request):
        method = request['method']                
        if method == "getBlockCount":
            count = self.minichain.getIndex()
            respond = {
                    "error" : 0,
                    "result" : count
                    }
            return json.dumps(respond)
        elif method == "getBlockHash":
            index = request['data']['block_height']
            result = self.minichain.getBlockHashByIndex(index)
            return self.RespondTemplate(0,result)

        elif method == "getBlockHeader":
            block_hash = request['data']['block_hash']
            result = self.minichain.getBlockHeader(block_hash)            
            if result is None:
                return self.RespondTemplate(1,"null")
            else:     
                return self.RespondTemplate(0,json.loads(result))

    def handle_rpc_client(self,client_socket, addr):
        while True:
            try: 
                data = client_socket.recv(4096)
                if len(data) > 0:
                    req = data.decode('utf-8')                    
                    request = json.loads(req)

                    respond = self.process_rpc_request(request)
                    client_socket.send(json.dumps(respond).encode('utf-8'))
                    ret = client_socket.recv(4096)
                    print(ret)
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
                    threading.Thread(target=self.handle_rpc_client, args=(c, addr)).start()
                except:
                    print("Exception happened")
                    traceback.print_exc()
            s.close()

    # handle the p2p client request.
    def handle_p2p_client(self,client_socket, addr):
        while True:
            try:
                data = client_socket.recv(4096)
                if len(data) > 0:
                    req = data.decode('utf-8')                    
                    request = json.loads(req)                    
                    respond = self.process_p2p_request(request,addr)                    
                    client_socket.send(json.dumps(respond).encode('utf-8'))
                    #data = client_socket.recv(2048)
                    #print(data)
                    #ret = json.loads(data.decode('utf-8'))
                    #if ret["error"] == 1:
                    #    print("Something error")                              
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
                    threading.Thread(target=self.handle_p2p_client, args=(c, addr[0])).start()
                except:
                    print("Exception happened")
                    traceback.print_exc()
            s.close()
    def start_node(self):
        print("[RUNNING]")
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
                """
                    if the genesis file does not exist, skip the checking.
                """
                if not os.path.isfile(file_name) and idx == 0 :
                    break
                idx = idx + 1
        # TODO
        # check if there are blocks in diretories
        # it might keep mine the hash with last time 
        # instead of creating the genesis block again.
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

        

if __name__ == '__main__':
    with open('config.json') as data:
        config = json.loads(data.read())
    
    neighbors = []
    neighbors.append(Neighbor(str(config['neighbor_list'][0])))
    ip, p2p_port = neighbors[0].getP2PConfig()
    
    diff = config['target']

    chain = minichain(diff)

    node1 = node(config['p2p_port'], config['user_port'], neighbors, chain)
    try:
        node1.start_node()
    except KeyboardInterrupt:
        sys.exit(1)

