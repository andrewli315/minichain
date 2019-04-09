import socket
import traceback
import time
import threading
from minichain import minichain
import json
import hashlib
import random
from neighbor import Neighbor

class node:
    def __init__(self, p2p_port, user_port, neighbors, minichain):
        self.p2p_port = p2p_port
        self.user_port = user_port
        self.neighbors = neighbors
        self.minichain = minichain
        self.flag = False
    def pauseMinig(flag):
        self.flag = flag

    def mining(self):
        print('[MINING]...')
        diff = self.minichain.getDifficult()
        version = self.minichain.getVersion()
        prev_hash = self.minichain.getPrevHash()
        merkle_root = self.minichain.getMerkleRoot()
        target = self.minichain.getTarget()
        m = hashlib.sha256()
        while True:
            if self.flag == True:
                print(self.flag)
                # check for data format                
                #block = getBlock()
                # TODO 
                # fill parameter into function call
                #minichain.insertBlock()            
                # update blockheader
            # uint32_t 4294967295          
            
            rand_num = str(random.randint(0,4294967295))
            nonce = '0'*(32-len(rand_num)) + rand_num
            block_header = version + prev_hash + merkle_root + target + nonce
            m.update(str(block_header).encode('utf-8'))
            m.update(nonce.encode('utf-8'))
            recent_hash = m.hexdigest()
            if self.checkHash(recent_hash):
                # insertBlock
                # sendBlock
                print(recent_hash)                            


    def checkHash(self,recent_hash):
        diff = str(self.minichain.getTarget()).index('1')
        prefix = recent_hash[:diff]
        if prefix == '0'*diff:
            return True
        else:
            return False
        
    """
        rpc api 
    """
    def getBlockCount(self):
        try:
            result = self.minichain.getBlockCount()
            ret_json = {
                    'error': 0,
                    'result': result
                }
            return ret_json
        except:
            ret_json = {
                    'error': 1,
                    'result': 0
                    }
            return ret_json
    
    def getBlockHash(self, index):
        try:
            result = getBlockByIndex(index)
            ret_json = {
                    'rror' : 0, 
                    'result': result                   
                    }
            return ret_json
        except:
            ret_json = {
                    'error' : 0,
                    'result' : 'null'
                    }
            return ret_json

    def getBlockHeader(self, header):
        try:
            result = getBlockByHash(header)
            ret_json = {
                    "error" : 0,
                    "result" : result
                    }
            return ret_json
        except:
            ret_json = {
                    "error" : 1,
                    "result" : "null"
                    }
            return ret_json
    """
        rpc api end
    """
    # handle the rpc client request.
    def getBlock(self):
        print("[GET Block]")

    def sendBlock(self):
        print("[SEND]")
    def handle_rpc_client(self,client_socket, addr):
        while True:
            try: 
                data = client_socket.recv(4096)
                if data:
                    print(data)
                else:
                    break
            except:
                client_socket.close()
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
                msg = client_socket.recv(4096)
                if data:
                    print(msg)
                else:
                    break
            except:
                client_socket.close()
        client_socket.close()


    def listen_p2p(self):
        print('[Listen for P2P Request]...')
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s :
            s.bind(('0.0.0.0', self.p2p_port))
            s.listen(100)
            while True:
                c, addr = s.accept()
                try:
                    threading.Thread(target=self.handle_p2p_client, args=(c, addr)).start()
                except:
                    print("Exception happened")
                    traceback.print_exc()
            s.close()

    def start_node(self):
        print("[RUNNING]")
        # start mining thread
        mining_thread = threading.Thread(target=self.mining)
        mining_thread.start()
        # start p2p server
        p2p_server_thread = threading.Thread(target=self.listen_p2p)
        p2p_server_thread.start()
        # start rpc server
        rpc_server_thread = threading.Thread(target=self.listen_rpc)
        rpc_server_thread.start()

        

if __name__ == '__main__':
    with open('config.json') as data:
        config = json.loads(data.read())
    
    neighbors = []
    neighbors.append(Neighbor(str(config['neighbor_list'][0])))
    ip, p2p_port = neighbors[0].getP2PConfig()
    
    diff = config['target']

    chain = minichain(diff)

    node1 = node(config['p2p_port'], config['user_port'], neighbors, chain)
    node1.start_node()

