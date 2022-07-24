#!/usr/bin/env python
# -*- coding: utf-8 -*-

from app import context as ctx
from app.db.db import CWalletDB
from app.utils.serdeser import ser_uint256, ser_int64, ser_str, deser_uint256, deser_int64, deser_str, uint256_from_str
from app.utils.baseutil import Hash, logg, unhexlify, hexlify
import ecdsa
import io





def pubkey_to_verifykey(pub_key, curve=ecdsa.SECP256k1):
    vk_string = unhexlify(pub_key[2:])
    return ecdsa.VerifyingKey.from_string(vk_string, curve=curve)


class Transaction(object):
    def __init__(self):
        self.nPrevTx = 0
        self.nValue = 0 
        self.nTo = b"" 
        self.nSignature = b"coinbase"



    def serialize(self, out_type=None):
        f = io.BytesIO()
        f.write(ser_uint256(self.nPrevTx))
        f.write(ser_int64(self.nValue))
        f.write(ser_str(self.nTo))

        if out_type == "hex":
            return hexlify(f.getvalue())
        return f.getvalue()



    def deserialize(self, f, nType=0, nVersion=1):
        self.nPrevTx = deser_uint256(f)
        self.nValue = deser_int64(f)
        self.nTo = deser_str(f)
        if not self.IsCoinBase():
            self.nSignature = f.getvalue()[-128:]



    def IsCoinBase(self):
        return self.nPrevTx == 0 * 32 



    def Print(self):
        print("Transaction(hash=%s, nValue=%d, nTo=%s)" % (self.GetHash("hex"), self.nValue, self.nTo))



    def GetHash(self, out_type=None):
        if out_type == "hex":
            return  Hash(self.serialize(), out_type="hex")
        return uint256_from_str(Hash(self.serialize(), out_type="hex").encode())




    def IsMine(self):
        reciptien = hexlify(self.nTo)
        return reciptien in ctx.mapKeys



    def checkInput(self):
        # does the input tx has enough coins ??
        old = ctx.mapTxIndex[self.nPrevTx]
        # total received 
        total_received = old[0] 
        # total spend
        total_spend = old[1]  

        # the available coins of the prev tx that the payer tries to spend
        nAvailableCoins = int(total_received) - int(total_spend)

        if total_received == total_spend:
            # payer have spend all their coins of the given txindex
            logg("Transaction(checkInput) PrevTxIndex {} for loose transaction has spend all their coins".format(self.nPrevTx))
            return False 



        if nAvailableCoins < self.nValue:
            # payer available coins are not enough
            logg("Transaction(checkInput) PrevTxIndex {} for loose transaction has not enough coins to spend".format(self.nPrevTx))
            return False 

        return True




    def CheckTransaction(self, pnode=False):


        if self.nValue >= ctx.MaxMoney:
            logg("CheckTransaction() - Failed, Transaction value too big")
            return False


        if not self.IsCoinBase():
            # check signature
            if self.nPrevTx not in ctx.mapTransactions:
                logg("CheckTransaction() - Prev tx {} not found".format(self.nPrevTx))
                return False 


            # This is a looose transaction, a loose tx is a tx between 2 parties.
            # Does we have the payer input tx ?
            if self.nPrevTx not in ctx.mapTxIndex:
                logg("AcceptBlock() PrevTxIndex {} for losse transaction not found".format(self.nPrevTx))
                return False 


            owner = hexlify(ctx.mapTransactions[self.nPrevTx].nTo)
            vk = pubkey_to_verifykey(owner)

            
            # this transaction must be signed with the private key of the input tx hash 
            if not vk.verify(self.nSignature, str(self.GetHash()).encode()):
                logg("CheckTransaction() Verify signature for tx {} failed".format(self.GetHash("hex")))
                return False


            if not self.checkInput():
                logg("CheckTransaction() checkInput failed for tx {} failed".format(self.GetHash("hex")))
                return False


        if self.IsMine():
            ret = CWalletDB().WriteTx(self)
            if ret:
                logg("Transaction {} added to wallet".format(self.GetHash("hex")))


        return True