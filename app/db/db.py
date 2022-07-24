#!/usr/bin/python
# Copyright (c) 2022 Papa Crouz
# Distributed under the MIT/X11 software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

from app import context as ctx


class CDB:
    def __init__(self, dbIn):
        self.db = dbIn


    def Write(self, key, value):
        with ctx._env.begin(write=True) as txn: 
            txn.put(key, value, db=self.db)

        # be sure that key was added to database 
        with ctx._env.begin(db=self.db) as txn:
            return txn.get(key) != None


    def Read(self, key):
        with ctx._env.begin(db=self.db) as txn:
            return txn.get(key)




class CsignaturesDB(CDB):
    def __init__(self):
        super().__init__(ctx._signatures_db)

    def WriteSignature(self, tx_hash, signature):
        key = b"key:" + str(tx_hash).encode()
        return self.Write(key, signature)


    def ReadSignature(self, tx_hash):
        key = b"key:" + str(tx_hash).encode()
        return self.Read(key)




class CWalletDB(CDB):
    def __init__(self):
        super().__init__(ctx._wallet_db)


    def WriteKey(self, public, private):
        key = b"key:" + public.encode()
        return self.Write(key, private.encode())


    def ReadKey(self, public):
        key = b"key:" + public.encode()
        return self.Read(key)


    def WriteTx(self, tx):
        key = b"tx:" + tx.GetHash("hex").encode()
        return self.Write(key, tx.serialize())


    def ReadTx(self, tx):
        key = b"tx:" + tx.GetHash("hex").encode()
        return self.Read(key)



        
class BlocksDB(CDB):
    def __init__(self):
        super().__init__(ctx._blocks_db)


    def WriteBlock(self, block):
        key = b"block:" + block.GetHash("hex").encode()
        blockDone = self.Write(key, block.serialize())

        for tx in block.nTxs:
            CsignaturesDB().WriteSignature(tx.GetHash(), tx.nSignature)

        return blockDone




    def ReadBlock(self, blockHash):
        key = b"block:" + blockHash.encode()
        return self.Read(key)


    def WriteTxIndex(self, txhash, received, spend):
        key = b"txindex:" + str(txhash).encode()
        value = b"received:" + str(received).encode() + b":spend:" + str(spend).encode()
        return self.Write(key, value)