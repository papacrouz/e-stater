from xmlrpc.server import SimpleXMLRPCServer
from xmlrpc.server import SimpleXMLRPCRequestHandler
import xmlrpc.client
import argparse
import base64
import os
import signal
import configparser


# local module
from main import *



# Restrict to a particular path.
class RequestHandler(SimpleXMLRPCRequestHandler):
    rpc_paths = ('/RPC2',)

    def authenticate(self, headers):
        auth = headers.get('Authorization') 
        try:
            (basic, _, encoded) = headers.get('Authorization').partition(' ')
        except:
            return 0        
        else:
            # Client authentication
            (basic, _, encoded) = headers.get('Authorization').partition(' ')
            
            assert basic == 'Basic', 'Only basic authentication supported'
            #    Encoded portion of the header is a string
            #    Need to convert to bytestring
            encodedByteString = encoded.encode()
            #    Decode Base64 byte String to a decoded Byte String
            decodedBytes = base64.b64decode(encodedByteString)
            #    Convert from byte string to a regular String
            decodedString = decodedBytes.decode()
            #    Get the username and password from the string
            (username, _, password) = decodedString.partition(':')
            #    Check that username and password match internal global dictionary

            config = configparser.ConfigParser()

            config.read("rpc.conf")
            rpc_user = config.get('server', 'rpc_user')
            rpc_pass = config.get('server', 'rpc_pass')
            
            if username == rpc_user and password == rpc_pass:                
                return True
            return False

    def parse_request(self):        
        if SimpleXMLRPCRequestHandler.parse_request(self):
            # next we authenticate
            if self.authenticate(self.headers):
                return True
            else:
                # if authentication fails, tell the client
                self.send_error(401, 'Authentication failed')
        return False

# Create server


class MyServer(SimpleXMLRPCServer):
    def __init__(self, bind_address, bind_port):
        # Create server
        self.server = SimpleXMLRPCServer((bind_address, bind_port),requestHandler=RequestHandler)
        self.server.register_introspection_functions()
        self.pid = os.getpid()

        self.server.register_function(lambda: os.getpid(), 'getpid')

        self.server.register_function(self.get_best_height, "getbestheight")
        self.server.register_function(self.get_best_hash, "getbesthash")
        self.server.register_function(self.get_difficulty, "getdifficulty")
        self.server.register_function(self.generate_new_key, "getnewkey")
        self.server.register_function(self.get_balance, "getbalance")

        self.server.register_function(self.start_mining, "startminer")
        self.server.register_function(self.stop_mining, "stopminer")
        self.server.register_function(self.miner_status, "minerstatus")
        self.server.register_function(self.get_information, "getinfo")






    
    ########################### Register functions #########################
    # get bestheight function
    def get_best_height(self): return str(ctx.bestHeight)
    # get besthash function 
    def get_best_hash(self): return str(ctx.mapBlockIndex[ctx.bestHash].GetHash("hex"))
    # get difficulty function 
    def get_difficulty(self): return CalculateDiff()
    # generate new key function 
    def generate_new_key(self): return GenerateNewKey()
    # get balance function 
    def get_balance(self): return str(getWalletBalance() /  ctx.COIN)
    # miner status function 
    def get_miner_status(self): return miner_status()



    def stop_server(self):
        os.kill(pid, signal.SIGTERM) #or signal.SIGKILL 


    # start mining function
    def start_mining(self):
        if not ctx.listfThreadRunning[0]:
            StartMining()
            time.sleep(4)
            if ctx.listfThreadRunning[0]:
                return "miner started"
        return "miner already running"
        

    def stop_mining(self):
        if ctx.listfThreadRunning[0]:
            ctx._miner_t.exit = True
            return "miner stoped"
        return "miner not running"


    def miner_status(self):
        if not ctx.listfThreadRunning[0]:
            return "Miner is not running"
        return "Miner is running"



    def get_information(self):
        mining = "True" if ctx.listfThreadRunning[0] else "False"
        data = {"version": ctx.nVersion, 
        "balance": str(getWalletBalance() /  ctx.COIN), 
        "blocks": str(ctx.bestHeight),
        "connections": str(ctx.total_connections),
        "difficulty": CalculateDiff(),
        "mining": mining
        }
        return data




    #########################################################################

    def serve_forever(self):
        self.server.serve_forever()
        
    def server_close(self):
        self.server.server_close()
        return 1


   



if __name__ == "__main__":

    config = configparser.ConfigParser()
    config.read("rpc.conf")

    rpc_host = config.get('server', 'rpc_host')
    rpc_port = config.get('server', 'rpc_port')




    server = MyServer(rpc_host, int(rpc_port))
    server.serve_forever()