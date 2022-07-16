# STATER

A simple implementation of Blockchain writen in python, using stater you can generate new blocks (pow sha256) and create transactions, node is not implemented yet so the new transactions and blocks cant be broadcasted to other peers

# Discussion 



# SETUP STATER
``` bash
git clone https://github.com/papacrouz/e-stater
cd e-stater
sudo pip3 install -r requirements.txt

```

# RUN STATER 
``` bash
cd e-stater
# start the daemon 
python3 rpc.py
```

# USAGE CURRENTLY SUPPORT ONLY RPC

# RPC

Stater rpc commands, note you should run python3 rpc.py first 
``` python 
python3 rpc-cli.py getbestheight -> Return the best height in the longest chain.
python3 rpc-cli.py getbesthash -> Return the best hash in the longest chain.
python3 rpc-cli.py getnewkey   -> Return a new key to receive coins 
python3 rpc-cli.py getbalance -> Return wallet balance.
python3 rpc-cli.py startminer -> Start generate new coins.
python3 rpc-cli.py stopminer -> Stop new coin generation.
python3 rpc-cli.py getinfo -> Return info 
{
    "balance": "0.0",
    "blocks": "0",
    "connections": "0",
    "difficulty": 0.00024413713253701452,
    "mining": "False",
    "version": "0.0.1"
}



``` 


## MINING

Miner function is working, you can start mining by running ``` python3 rpc-cli.py startminer ``` command, you can check your minting proccess by running ``` python3 rpc-cli.py getinfo ``` if you are mining the response should have the miner field set to True, also you will notice your both wallet balance block height will start increment, the minting operation can be stoped using the ``` python3 rpc-cli.py stopminer ``` command
