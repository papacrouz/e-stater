# STATER

A simple implementation of Blockchain writen in python, using stater you can generate new blocks (pow sha256) and create transactions, node is not functionallity working yet, so only blocks containig conbase transactions only can be broadcasted between peers.

# Discussion 



# SETUP STATER
``` bash
git clone https://github.com/papacrouz/e-stater
cd e-stater
sudo pip3 install -r requirements.txt

```

# RUN STATER GUI
``` bash
cd e-stater
# start the daemon 
python3 stater-gui.py
```

This will start client and automatically will connect to node located on peers.dat and will srart syncing, i've set an aws instance with mining enabled for testing, if you dont want connect to this node, just clear anything on peers,dat file, or add your own node, if you sync with my node and is there any issue please raise an issue here on github. 

![This is an image](https://i.ibb.co/tC3WzMM/stater.png)

# STATER SUPPORT RPC

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

Miner function is working, you can start mining by clicking the start mining button in stater-gui.py or using rpc   by running ``` python3 rpc-cli.py startminer ``` command, you can check your minting proccess by running ``` python3 rpc-cli.py getinfo ``` if you are mining the response should have the miner field set to True, also you will notice your both wallet balance block height will start increment, the minting operation can be stoped using the ``` python3 rpc-cli.py stopminer ``` command
