import json

class Neighbor:
    def __init__(self, config):
        # load json string
        config = config.replace("'","\"")
        json_str = json.loads(config)

        # store neighbor's configure
        self.ip = json_str['ip']
        self.p2p_port = json_str['p2p_port']
        self.user_port = json_str['user_port']
    def info(self):
        print('ip : ' + self.ip)
        print('p2p port : ' + str(self.p2p_port))     
    def getAddr(self):
        return self.ip
    def getp2pPort(self):
        return self.p2p_port
    def getP2PConfig(self):
        return self.ip, self.p2p_port

    def getRPCConfig(self):
        return self.ip, self.user_port


