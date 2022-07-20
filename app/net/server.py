#!/usr/bin/python
# Copyright (c) 2022 Papa Crouz
# Distributed under the MIT/X11 software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

import socket 
import threading
import _thread
import time


from app import context as ctx
from app.net import messages


_nodeid = messages.generate_nodeid()


class Client(threading.Thread):
    def __init__(self, socket, address, id, signal):
        threading.Thread.__init__(self)
        self.socket = socket
        self.address = address
        self.id = id
        self.signal = signal
        self.state= "GETHELLO"

        self.remote_nodeid = None
        self.remote_node_protocol_version = None
        self.myNodeid = _nodeid

        self.lastPingSend = 0
        self.lastPongReceived = 0 

        _thread.start_new_thread(self.send_Ping, ())

    
    def __str__(self):
        return str(self.id) + " " + str(self.address)
    
   
    def run(self):
        while self.signal:

            data = self.socket.recv(2048)
            for line in data.splitlines():
                line = line.strip()
                envelope = messages.read_envelope(line)
                if self.state in ["GETHELLO", "SENTHELLO"]:
                    # Force first message to be HELLO or crash
                    if envelope['msgtype'] == 'hello':
                        hello = messages.read_message(line)
                        self.remote_nodeid = hello['nodeid']
                        self.remote_node_protocol_version = hello["protocol"]

                        if self.state == "GETHELLO":
                            msg = messages.create_ackhello(self.myNodeid)
                            self.socket.sendall(msg.encode())
                            self.state = "READY"

                else:
                    if envelope['msgtype'] == 'sync':
                        msg = messages.create_sync(self.myNodeid, ctx.bestHeight, ctx.bestHash)
                        self.socket.sendall(msg.encode())

                    elif envelope['msgtype'] == 'givemeblocks':
                        data = messages.read_message(line)
                        client_best_hash = data["besthash"]
                        if client_best_hash in ctx.mapBlockIndex:
                           # client seems to be run in correct chain 
                           # sync him with our chain 
                           

                           # signature to include in block message 
                           signatures = []
                           
                           for block in ctx.mapBlockIndex:
                            if ctx.mapBlockIndex[block].hashPrevBlock == client_best_hash:
                                block_network = ctx.mapBlockIndex[block]
                                if len(block_network.nTxs) > 1:
                                    for x in range(1, len(block_network.nTxs)):
                                        signatures.append(block_network.nTxs[x].nSignature.hex())


                                ret = block_network.serialize(out_type="hex")
                                msg = messages.create_send_block(self.myNodeid, ret.decode("utf-8"), signatures)
                                self.socket.sendall(msg.encode())

                    elif envelope['msgtype'] == 'relay_txs':
                        logg("Server() Got a tx from client")


                    elif envelope['msgtype'] == 'pong':
                        self.lastPongReceived = int(time.time())

                    elif envelope['msgtype'] == "getaddr":
                        with open("peers.dat", "r") as peers:
                            lines = peers.readlines()
                            msg = messages.create_addr(self.myNodeid, lines)
                            self.socket.sendall(msg.encode())





    def send_Ping(self):
        # send ping to client
        while True:
            pass



#Wait for new connections
def newConnections(socket):
    while True:
        sock, address = socket.accept()
        ctx.connections.append(Client(sock, address, ctx.total_connections, True))
        ctx.connections[len(ctx.connections) - 1].start()
        print("New connection at ID " + str(ctx.connections[len(ctx.connections) - 1]))
        ctx.total_connections += 1