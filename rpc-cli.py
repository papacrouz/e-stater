import xmlrpc.client
import argparse
import time 
import json
import sys
import socket


rpc_user = "your_user_name"
rpc_pass = "a_strong_password"
rpc_port = "8901"


availables_cmds = ["getpid", "getbestheight", "getbesthash", "getdifficulty", "getinfo", "getbalance", "getnewkey",
                   "startminer", "stopminer", "minerstatus"]

 
cmds = """
--------------   Blockchain --------------
"getbestheight - Reurn the best height in the longest chain"
"getbesthash - Reurn the best hash in the longest chain"
"getdifficulty - Reurn the current difficulty"
"getinfo - Return info

"--------------  Wallet --------------"
"getbalance - Return wallet balance"
"getnewkey - Reurn a new zap key"

"--------------  Mining --------------"
"startminer - Starts miner"
"stopminer - Stops miner"
"minerstatus - Return miner status

"""

server = xmlrpc.client.ServerProxy('http://{}:{}@localhost:{}'.format(rpc_user, rpc_pass, rpc_port))


def run_rpc_command(params):
    cmd = params[0]
    func = getattr(server, cmd)
    r = func(*params[1:])
    print (json.dumps(r, indent=4, sort_keys=True))



parser = argparse.ArgumentParser()
parser.add_argument('command', nargs='*', default=[], help='send a command to the server')
args = parser.parse_args()

if len(args.command) >= 1:
    if args.command[0] == "help":
        print(cmds)
    else:

        if args.command[0] in availables_cmds:
            try:
                run_rpc_command(args.command)
            except socket.error:
                print ("server not running")
                sys.exit(1)
            sys.exit(0)
        print("Unknow command {}, use {} help for available commands".format(args.command[0], sys.argv[0]))


"""
print(s.getbesthash())  
print(s.getdifficulty())  
print(s.getnewkey())  
print(s.getbalance())
"""