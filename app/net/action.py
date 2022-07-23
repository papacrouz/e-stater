#!/usr/bin/python
# Copyright (c) 2022 Papa Crouz
# Distributed under the MIT/X11 software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

import threading
import _thread
import socket 


from app import context as ctx
from app.net.client import *
from app.net.server import newConnections
from app import thread
from app.utils.baseutil import logg

from twisted.internet import reactor, protocol
from twisted.internet.task import LoopingCall
from app import thread





def startNode(client=False, server=False):
	#Get host and port
    
    if server:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        ctx.hlistenSocket = sock 
        sock.bind((ctx.host, ctx.port))
        sock.listen(5)

        #Create new thread to wait for connections
        ctx.newConnectionsThread = thread.AcceptConnectionsThread(sock)
        ctx.newConnectionsThread.start()

        ctx.listWorkThreads.append((ctx.newConnectionsThread, "node_thread"))



    if client:
        ctx._connections_t = thread.OpenConnectionsThread(None)
        ctx._connections_t.start()
        logg("[*] Stater open connections thread started")
        ctx.listWorkThreads.append((ctx._connections_t, "client_thread"))


    return True 
    
     



def StartMining():
    ctx._miner_t = thread.CoinMinerThread(None)
    ctx._miner_t.start()
    logg("[*] Stater miner thread started")
    ctx.listWorkThreads.append((ctx._miner_t, "miner_thread"))