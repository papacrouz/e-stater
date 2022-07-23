#!/usr/bin/env python
# -*- coding: utf-8 -*-


from app import context as ctx
from app.net import client 
from app.utils.baseutil import logg
from app.block.miner import StaterMiner
from app.net.client import EchoClient
from app.net.server import newConnections


from signal import signal, SIGINT
from twisted.internet import reactor, protocol
from twisted.internet.task import LoopingCall
import threading
import traceback
import _thread
import time
import sys


opMapper = {0: "Miner thread", 1: "Client thread", 2: "Server thread"}


shutdownLock = threading.Lock()



def shutdown():
    with shutdownLock:
        if ctx.fShutdown:
            return

        ctx.fShutdown = True
        if ctx.hlistenSocket is not None:
            ctx.hlistenSocket.close()
        




def check_for_shutdown(t):
    # handle shutdown 
    n = t.n
    if ctx.fShutdown:
        if n != -1:
            ctx.listfThreadRunning[n] = False
            t.exit = True
            print("Exiting {}".format(opMapper[n]))







class ExitedThread(threading.Thread):
    def __init__(self, arg, n):
        super(ExitedThread, self).__init__()
        self.exit = False
        self.arg = arg
        self.n = n

    def run(self):
        self.thread_handler(self.arg, self.n)
        pass

    def thread_handler(self, arg, n):
        while True:
            check_for_shutdown(self)
            if self.exit:
                break
            ctx.listfThreadRunning[n] = True
            try:
                self.thread_handler2(arg)
            except Exception as e:
                logg("ThreadHandler()")
                logg(e)
            ctx.listfThreadRunning[n] = False

            time.sleep(5)
            pass

    def thread_handler2(self, arg):
        raise NotImplementedError("must impl this func")

    def check_self_shutdown(self):
        check_for_shutdown(self)

    def try_exit(self):
        self.exit = True
        ctx.listfThreadRunning[self.n] = False
        pass




class CoinMinerThread(ExitedThread):
    def __init__(self, arg=None):
        super(CoinMinerThread, self).__init__(arg, n=0)

    def thread_handler2(self, arg):
        self.thread_stater_miner(arg)

    def thread_stater_miner(self, arg):
        ctx.listfThreadRunning[self.n] = True
        check_for_shutdown(self)
        try:
            ret = StaterMiner(self)
            logg("[*] Miner returned %s\n\n" % "true" if ret else"false")
        except Exception as e:
            logg("[*] Miner()")
            logg(e)
            traceback.print_exc()
        ctx.listfThreadRunning[self.n] = False
    pass  




class OpenConnectionsThread(ExitedThread):
    def __init__(self, arg=None):
        super(OpenConnectionsThread, self).__init__(arg, n=1)

    def thread_handler2(self, arg):
        self.thread_stater_openConnections(arg)

    def thread_stater_openConnections(self, arg):
        ctx.listfThreadRunning[self.n] = True
        check_for_shutdown(self)
        try:
            ret = openConnections(self)
        except Exception as e:
            logg(e)
            traceback.print_exc()
        ctx.listfThreadRunning[self.n] = False

    pass




class AcceptConnectionsThread(ExitedThread):
    def __init__(self, arg=None):
        super(AcceptConnectionsThread, self).__init__(arg, n=2)

    def thread_handler2(self, arg):
        self.thread_stater_acceptConnections(arg)

    def thread_stater_acceptConnections(self, sock):
        ctx.listfThreadRunning[self.n] = True
        check_for_shutdown(self)
        try:
            ctx.server_thread = threading.Thread(target = newConnections, args = (sock,))
            ctx.server_thread.start()
        except Exception as e:
            logg(e)
            traceback.print_exc()
        ctx.listfThreadRunning[self.n] = False

    pass




def start_client(host, port):
    reactor.connectTCP(host, port, EchoFactory())
    reactor.run() 


def openConnections(t):

    while True:
        t.check_self_shutdown()
        if t.exit:
            break

        with open("peers.dat", "r") as peers:
            lines = peers.readlines()
            
            for peer in lines:
                host, port = peer.strip().split(":")

                if len(ctx.connectionsOpened) == 0:
                    # try to connect to all nodes located in peers.dat file 

                    _thread.start_new_thread(start_client, (host, int(port)))
                else:
                    for addr in ctx.connectionsOpened:
                        if addr.host != host:
                            if host not in ctx.connectionsFailed:
                                # Connect only to nodes that we are not already connected, and 
                                # not marked as failed.
                                _thread.start_new_thread(start_client, (host, int(port)))

        time.sleep(30)








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