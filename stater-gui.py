#!/usr/bin/env python  
# Copyright (c) 2022-2023 Papa Crouz
# Distributed under the MIT/X11 software license, see the accompanying
# file license http://www.opensource.org/licenses/mit-license.php.


from tkinter import *
from tkinter import ttk
import tkinter as tk
from tkinter import messagebox
from tkinter import simpledialog
from datetime import datetime
import _thread
import tkinter.messagebox

from main import *

class silme:

    def __init__(self, root):
        self.root = root
        self.frame = Frame(self.root)
        self.frame.pack()
        self.c = StringVar()
        self.t = StringVar()
        self.addr_ = StringVar()
        self.balance_ = StringVar()
        self.connection_ = StringVar()
        self.startorstopmining_ = StringVar()
        self.binfo_ = StringVar()


        


        self.addr()
        #self.mining()
        self.balance()
        self.send()
        self.blockchain()
        self.mining()




        _thread.start_new_thread(self._update, ())

        #_thread.start_new_thread(start_server, ())
        #_thread.start_new_thread(start_client, ())
        #StartOpenConnections()
        


        




    def blockchaininfo(self):
        return "Height: %d | Difficulty: %f | Incomming connections: %d | Outgoing connections: %d " %(ctx.bestHeight, CalculateDiff(), ctx.total_connections, ctx.connected_to)
        

    def _update(self):
        addr = GenerateNewKey()
        while True:
            self.addr_.set(addr)
            self.balance_.set(getWalletBalance() / ctx.COIN)
            self.binfo_.set(self.blockchaininfo())
            self.startorstopmining_.set(self.sosm())
            time.sleep(3)


    def sosm(self):
        if ctx.fMiner:
            return "Stop"
        else:
            return "Start"



    
    def addr(self):
        addr_f = LabelFrame(self.frame, text="Pubkey", padx=5, pady=5)
        addr_f.grid(sticky=E+W)
        Entry(self.frame, state="readonly", textvariable=self.addr_, width=80).grid(in_=addr_f)



    def balance(self):
        addr_balance = LabelFrame(self.frame, text="Balance", padx=5, pady=5)
        addr_balance.grid(sticky=E+W)
        Entry(self.frame, state="readonly", textvariable=self.balance_, width=50).grid(in_=addr_balance)


    def mining(self):
        mining_f = LabelFrame(self.frame, text="Mining", padx=3, pady=5)
        mining_f.grid(sticky=E+W)
        send_b = Button(self.frame, command=self.__mining, textvariable=self.startorstopmining_).grid(in_=mining_f, row=0, column=4, sticky=W+E)



    def blockchain(self):
        blockchain_info = LabelFrame(self.frame, text="Blockchain Info", padx=5, pady=5)
        blockchain_info.grid(sticky=E+W)
        Entry(self.frame, state="readonly", textvariable=self.binfo_, width=90).grid(in_=blockchain_info)





    def send(self):
        send_f = LabelFrame(self.frame, text="Send Coin", padx=5, pady=15)
        send_f.grid(sticky=E+W)
        to_l = Label(self.frame, text="To: ").grid(in_=send_f)
        self.to = Entry(self.frame)
        self.to.grid(in_=send_f, row=0, column=1, sticky=W)
        amount_l = Label(self.frame, text="Amount: ").grid(in_=send_f, row=0, column=3, sticky=W)
        self.amount = Entry(self.frame, width=4)
        self.amount.grid(in_=send_f, row=0, column=4, sticky=W)
        Label(self.frame, text="   ").grid(in_=send_f, row=0, column=5)
        Label(self.frame, text="   ").grid(in_=send_f, row=0, column=2)
        send_b = Button(self.frame, command=self._send, text="Send").grid(in_=send_f, row=0, column=8, sticky=W+E)


            
    def _send(self):
        amount = self.amount.get()
        recipt = self.to.get()


        
        if not SendMoney(recipt, int(amount) * ctx.COIN):
            messagebox.showinfo("Error", "Cant create transaction")
            return 0
        else:
            messagebox.showinfo("Sending...", "Your coins are being sent, this could take a while.")


    def mining(self):
        mining_f = LabelFrame(self.frame, text="Mining", padx=3, pady=5)
        mining_f.grid(sticky=E+W)
        send_b = Button(self.frame, command=self.__mining, textvariable=self.startorstopmining_).grid(in_=mining_f, row=0, column=4, sticky=W+E)


    def __mining(self):

    
        if self.startorstopmining_.get() == "Stop":
            if ctx.listfThreadRunning[0] == True:
                ctx._miner_t.exit = True
                ctx.fMiner = False
                messagebox.showinfo("Mining...", "Stater stoped.") 

            
        elif self.startorstopmining_.get() == "Start":
            ctx.fMiner = True
            StartMining()

            messagebox.showinfo("Mining...", "StarterMiner Started.") 




if __name__ == "__main__":

   
    root = Tk()
    root.geometry("655x330+350+100")
    silme(root=root)
    root.title("Stater Client")
    root.mainloop()

