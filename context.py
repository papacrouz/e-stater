import lmdb
import os
from util import *
import threading

if not os.path.exists(GetAppDir()):
	try:
		os.mkdir(GetAppDir())
	except Exception as e:
		sys.exit(logg("Unable to create data directory"))
	else:
		pass

_env = lmdb.open(GetAppDir() + '/stater.lmdb', max_dbs=10) 
_blocks_db = _env.open_db(b'blocks')
_wallet_db = _env.open_db(b'wallet')
_signatures_db = _env.open_db(b'signatures')
_miner_t = None


# <pub> -> <priv> 
mapKeys = {}
mapKeysLock = threading.RLock()

mapWalletTransactions = {}
mapWalletTransactionsLock = threading.RLock()


mapBlockIndex = {}
mapHeight = {}
height_map = {}


mapTransactions = {}
bestHash = None
bestHeight = -1
mapTxIndex = {}

COIN = 100000000
MaxMoney = 21000000 * COIN

readForRelayTransactions = []

hashGenesisBlock = b"00000f9ab97717c5d1101811f9a805534436048aa88a5bb7e1bf9c854b4fee44"


fMiner = False
fShutdown = False 
listfThreadRunning = [False] * 10

# blocks that we mine
readForRelayBlocks = []

connectedClients = []

_network_t = None

lastPingSend = {}
lastPongReceived = {}


lockClients = threading.RLock()
connections = []
total_connections = 0
nVersion = "0.0.1"