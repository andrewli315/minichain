import json
import socket
import traceback
import time
from minichain import minichain



def main():
    host = '127.0.0.1'
    port = 4444
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect((host,port))

    payload = {
            "method" : "getBlockCount" 
            }
    print(json.dumps(payload))
    client.send(json.dumps(payload).encode('utf-8'))
    time.sleep(1)
    respond = client.recv(4096)
    result = json.loads(respond.decode('utf-8'))
    print(result)
    client.close()


if __name__ == '__main__':
    main()
