#!/usr/bin/python
# Copyright (c) 2022 Papa Crouz
# Distributed under the MIT/X11 software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

from app import context as ctx
from app.block.block import Block
from app.block.tx.tx import Transaction
from app.utils.baseutil import Hash, hexlify, unhexlify

import ecdsa



def getWalletBalance():
    balance = 0

    with ctx.mapWalletTransactionsLock:
        for tx in ctx.mapWalletTransactions:
            a = int(ctx.mapTxIndex[tx][0])
            b = int(ctx.mapTxIndex[tx][1])
            balance += a - b 

    return balance



def GetWalletTxBalance(tx):
    a = int(ctx.mapTxIndex[tx][0])
    b = int(ctx.mapTxIndex[tx][1])
    return a - b 




def GetReceivedTransactions():
    r = []
    for tx in ctx.mapWalletTransactions:
        if hexlify(ctx.mapWalletTransactions[tx].nTo) in ctx.mapKeys:
            r.append(ctx.mapWalletTransactions[tx])
    return r






def SendMoney(to, amount):


    found = False

    txindex = None


    with ctx.mapWalletTransactionsLock:
        for tx in ctx.mapWalletTransactions:
            collected = GetWalletTxBalance(tx)
            if collected >= amount:
                txindex = tx
                found = True 
                break

    if found:
        tx = Transaction()
        tx.nPrevTx = txindex
        tx.nValue = amount 
        tx.nTo = unhexlify(to)
        # get the input pubkey key owner 
        owner = ctx.mapTransactions[txindex].nTo
        # get the private key 
        privkey = ctx.mapKeys[hexlify(owner)]
        # import the priv key 
        sk = ecdsa.SigningKey.from_string(unhexlify(privkey), curve=ecdsa.SECP256k1)
        # sign the prev tx 
        signature = sk.sign(str(tx.GetHash()).encode())


        tx.nSignature = signature

        ctx.memPool.append(tx)

        return True 
    return False