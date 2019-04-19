import json
import os
import sys
import socket

def main():
    host = '127.0.0.1'
    port = 4443
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect((host,port))

    with open('../blocks/3.json','r') as data:
        block = json.load(data)
    prev_hash = block['block_header']['prev_block']
    block_hash = block['block_hash']
    payload = {
            "method" : "getBlocks",
            "data" :{
                "hash_count" : 3,
                "hash_begin" : '0'*64,
                "hash_stop"  : block_hash
                }
            }
    payload = json.dumps(payload)
    print(payload)
    client.send(payload.encode('utf-8'))
    respond = client.recv(4096)
    result = json.loads(respond.decode('utf-8'))
    result = json.loads(result)
    
    for item in result["result"]:
        print(item)
    
    
    client.close()

if __name__ == '__main__':
    main()
