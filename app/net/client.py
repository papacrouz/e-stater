#!/usr/bin/python
# Copyright (c) 2022 Papa Crouz
# Distributed under the MIT/X11 software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.


from app import context as ctx
from app.block.block import Block
from app.utils.baseutil import logg, unhexlify

from twisted.internet import reactor, protocol
from twisted.internet.task import LoopingCall

from app.net import messages 



class EchoClient(protocol.Protocol):
  def __init__(self):
    self._nodeid = messages.generate_nodeid()
    self.lc_sync = LoopingCall(self.send_SYNC)
    self.lc_getaddr = LoopingCall(self.send_GetPeers)
    self.lc_relay_txs = LoopingCall(self.send_RelayTransactions)

    self._version = 1 
    self._protocolVersion = 1




  def write(self, line):
    self.transport.write(line.encode() + b"\n")


  def connectionMade(self):
    # build a hello message 
    hello = messages.create_hello(self._nodeid, self._version, self._protocolVersion)
    self.write(hello)

  def dataReceived(self, data):
    for line in data.splitlines():
      line = line.strip()
      envelope = messages.read_envelope(line)
      if envelope['msgtype'] == 'ackhello':
        # ask server if we need sync every 5 seconds
        print("Client() - Got Hello message from server")
        self.lc_sync.start(10, now=False)
        self.lc_getaddr.start(10, now=False)
        self.lc_relay_txs.start(10, now=False)


      elif envelope['msgtype'] == 'sync':
        print("Client() - Got sync message from server")
        data = messages.read_message(line)

        if data["bestheight"] > ctx.bestHeight:
          print("we are {} blocks behind, sync needed".format(data["bestheight"] - ctx.bestHeight))
          # ask server for blocks 
          msg = messages.create_ask_blocks(self._nodeid, ctx.bestHash)
          self.write(msg)

        elif data["bestheight"] == ctx.bestHeight:
          print("we are synced with server, server height {} our {}".format(data["bestheight"], ctx.bestHeight))

        elif data["bestheight"] < ctx.bestHeight:
          print("holy shit server is behind {} blocks".format(ctx.bestHeight - data["bestheight"]))

      elif envelope['msgtype'] == 'getblock':
        data = messages.read_message(line)

        signatures = data["signatures"]

        


        block = Block()
        block.deserialize(unhexlify(data["raw"].encode()))


        for tx in block.nTxs:
            if not tx.IsCoinBase():
                tx.nSignature = bytes.fromhex(signatures[0])
                signatures.remove(signatures[0])


        if block.AcceptBlock(pnode=True):
          print("block from peer accepted, new height is {}".format(ctx.bestHeight))

      elif envelope['msgtype'] == 'ping':
        print("got ping message from server")
        msg = messages.create_pong(self._nodeid)
        self.write(msg)

      elif envelope['msgtype'] == 'addr':
        print("Got addreeses from node server")
        data = messages.read_message(line)
        nodes = data["nodes"]

        nodesToAdd = []

        with open("peers.dat", "r") as peers:
            local = peers.readlines()
            for node in nodes:
                if node not in local:
                    nodesToAdd.append(node.strip())


        if len(nodesToAdd) > 0:
            with open("peers.dat", "a") as peers:
                peers.write("\n".join(map(str, nodesToAdd)))

  

  def send_GetPeers(self):
    print("[>] Asking for peers")
    msg = messages.create_getaddr(self._nodeid)
    self.write(msg)


  def send_SYNC(self):
    print("[>] Asking if we need sync")
    # Send a sync message to remote peer 
    # A sync message contains our best height and our besthash
    sync = messages.create_sync(self._nodeid, ctx.bestHeight, ctx.bestHash)
    self.write(sync)

  

  def send_RelayTransactions(self):
    print("[>] Sending our transactions to server")
    if len(ctx.memPool) > 0:
        msg = messages.create_relay_txs(self._nodeid, ctx.memPool)
        self.write(sync)




class EchoFactory(protocol.ClientFactory):
  def buildProtocol(self, addr):
    ctx.connected_to +=1
    ctx.connectionsOpened.append(addr)
    return EchoClient()

  def clientConnectionFailed(self, connector, reason):
    # This should be called when the connection to server fail to estabilished
    ctx.connectionsFailed.append(connector.host) 
    #reactor.stop()
    

  def clientConnectionLost(self, connector, reason):
    # This should be called when the connection to server have estabilished
    # and for droped unexpected
    ctx.connected_to  = ctx.connected_to -1
    #reactor.stop() 




