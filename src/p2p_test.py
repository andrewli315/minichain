import json
import os
import sys
import socket

def main():
    host = '127.0.0.1'
    port = 4443
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect((host,port))

    with open('../blocks/1.json','r') as data:
        block = json.load(data)
    prev_hash = block['block_header']['prev_block']
    block_hash = block['block_hash']
    payload = {
            "method" : "getBlocks",
            "data" :{
                "hash_count" : 1,
                "hash_begin" : prev_hash,
                "hash_stop"  : block_hash
                }
            }
    payload = json.dumps(payload)
    print(payload)
    client.send(payload.encode('utf-8'))
    respond = client.recv(4096)
    result = json.loads(respond.decode('utf-8'))
    print(result)
    client.close()

if __name__ == '__main__':
    main()
