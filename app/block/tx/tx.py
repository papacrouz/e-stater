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




    def CheckTransaction(self, pnode=False):


        if self.nValue >= ctx.MaxMoney:
            logg("CheckTransaction() - Failed, Transaction value too big")
            return False


        if not self.IsCoinBase():
            # check signature
            if self.nPrevTx not in ctx.mapTransactions:
                logg("CheckTransaction() - Prev tx {} not found".format(self.nPrevTx))
                return False 


            owner = hexlify(ctx.mapTransactions[self.nPrevTx].nTo)
            vk = pubkey_to_verifykey(owner)

            
            # this transaction must be signed with the private key of the input tx hash 
            if not vk.verify(self.nSignature, str(self.GetHash()).encode()):
                logg("CheckTransaction() Verify signature for tx {} failed".format(self.GetHash("hex")))
                return False


        if self.IsMine():
            ret = CWalletDB().WriteTx(self)
            if ret:
                logg("Transaction {} added to wallet".format(self.GetHash("hex")))


        return True