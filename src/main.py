import json
import sys
from neighbor import Neighbor
from minichain import minichain
from node import node
from wallet import wallet
def main():
    with open('config.json') as data:
        config = json.load(data)
    
    neighbors = []
    for item in config['neighbor_list']:
        neighbors.append(Neighbor(str(item)))
        ip, p2p_port = neighbors[0].getP2PConfig()
    
    diff = config['target']
    beneficiary = config['beneficiary']
    delay = config['delay']
    is_miner = config['mining']
    public_key = config['wallet']['public_key']
    private_key = config['wallet']['private_key']
    fee = config['fee']

    chain = minichain(diff)
    user_wallet = wallet(public_key,private_key)
    node1 = node(config['p2p_port'], config['user_port'], neighbors, chain,beneficiary, wallet,fee, delay, is_miner)
    try:
        node1.start_node()
    except KeyboardInterrupt:
        sys.exit(1)
    except :
        print("[ERROR] UNKNOWN ERROR")
        sys.exit(1)

if __name__ == '__main__':
    main()
