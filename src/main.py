import sys
def main():
    with open('config.json') as data:
        config = json.loads(data.read())
    
    neighbors = []
    for item in config['neighbor_list']:
        neighbors.append(Neighbor(str(item)))
        ip, p2p_port = neighbors[0].getP2PConfig()
    
    diff = config['target']

    chain = minichain(diff)

    node1 = node(config['p2p_port'], config['user_port'], neighbors, chain)
    try:
        node1.start_node()
    except KeyboardInterrupt:
        sys.exit(1)
    except :
        print("[ERROR] UNKNOWN ERROR")
        sys.exit(1)

if __name__ == '__main__':
    main()