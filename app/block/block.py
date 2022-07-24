#!/usr/bin/python
# Copyright (c) 2022 Papa Crouz
# Distributed under the MIT/X11 software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.


from app import context as ctx
from app.block.tx.tx import Transaction
from app.db.db import BlocksDB
from app.utils.serdeser import ser_int, ser_uint256, ser_uint, deser_uint256, uint256_from_str, deser_int, deser_uint, deser_list, ser_list, hexser_uint256
from app.utils.baseutil import GetNextWorkRequired, Hash, hexlify, unhexlify, logg
import io


class Block(object):
    def __init__(self):
        self.nVersion = 1 
        self.hashPrevBlock = 0
        self.hashMerkleRoot = 0 
        self.nTime = 0 
        self.nBits = 0 
        self.nNonce = 0 

        # transactions 
        self.nTxs = list()

        self.l_merkle_tree = list()


    def serialize(self, nType=0, nVersion=1, header=False, out_type=None):
        s = io.BytesIO()
        s.write(ser_int(self.nVersion))
        s.write(ser_uint256(self.hashPrevBlock))
        s.write(ser_uint256(self.hashMerkleRoot))
        s.write(ser_uint(self.nTime))
        s.write(ser_uint(self.nBits))
        s.write(ser_uint(self.nNonce))
        if header and out_type == "hex":
            return hexlify(s.getvalue())
        if header and not out_type:
            return s.getvalue()

        if not header:
            s.write(ser_list(self.nTxs, cls=Transaction, nType=0, nVersion=1))

        if not header and out_type == "hex":
            return hexlify(s.getvalue())
        return s.getvalue()


    def GetHash(self, out_type="uint256", header=False):
        if out_type == 'hex':
            return Hash(self.serialize(), out_type="hex")
        return uint256_from_str(Hash(self.serialize(), out_type="hex").encode())



    def deserialize(self, f, nType=0, nVersion=1, includeSig=False):
        f = io.BytesIO(f)
        self.nVersion = deser_int(f)
        self.hashPrevBlock = deser_uint256(f)
        self.hashMerkleRoot = deser_uint256(f)
        self.nTime = deser_uint(f)
        self.nBits = deser_uint(f)
        self.nNonce = deser_uint(f)

        self.nTxs = deser_list(f, Transaction, nType=nType, nVersion=nVersion)



    def Print(self):
        s = 'Block(hash={}, ver={}, hashPrevBlock={}, hashMerkleRoot={}, nTime={}, nBits={}, nNonce={}, vtx={})\n' \
         .format(self.GetHash("hex").encode(), self.nVersion,  unhexlify(hexser_uint256(self.hashPrevBlock)), hexser_uint256(self.hashMerkleRoot), self.nTime, self.nBits, self.nNonce, len(self.nTxs))

        print(s)



    def BuildMerkleTree(self):
        self.l_merkle_tree = list(map(lambda tx: tx.GetHash(out_type='hex'), self.nTxs))
        size = len(self.nTxs)
        j = 0
        while True:
            if size <= 1:
                break
            for i in range(0, size, 2):
                i2 = min(i + 1, size - 1)
                self.l_merkle_tree.append(Hash(self.l_merkle_tree[j + i].encode(), self.l_merkle_tree[j + i2].encode(), out_type='str'))
                pass
            j += size
            size = 1

        
        try:
            ptr = uint256_from_str(self.l_merkle_tree[-1]) if self.l_merkle_tree else 0
        except Exception as e:
            ptr = uint256_from_str(self.l_merkle_tree[-1].encode()) if self.l_merkle_tree else 0
        else:
            pass
        
        return ptr




    def CheckBlock(self, pnode=False):

        if len(self.nTxs) == 0:
            logg("CheckBlock failed, not transactions found")
            return False 

        if not self.nTxs[0].IsCoinBase():
            logg("CheckBlock failed, first tx is not coinabase")
            return False 

        for x in range(1, len(self.nTxs)):
            if self.nTxs[x].IsCoinBase():
                logg("CheckBlock failed, more than one coinabase tx found")
                return False 

        for i in range(0, len(self.nTxs)):
            if not self.nTxs[i].CheckTransaction(pnode):
                logg ("CheckBlock() : CheckTransaction failed for tx index:%d" % i)
                return False

        if self.hashMerkleRoot != self.BuildMerkleTree():
            logg("CheckBlock() : hashMerkleRoot mismatch")
            return False

        return True



    def AcceptBlock(self, pnode=False):
        # Check for duplicate
        if self.GetHash() in ctx.mapBlockIndex:
            logg("AcceptBlock() - Already have block {}".format(self.GetHash("hex")))
            return False

        # Get prev block index

        if self.hashPrevBlock not in ctx.mapBlockIndex and self.GetHash("hex").encode() != ctx.hashGenesisBlock:
            logg("AcceptBlock() - Prevblock {} not found".format(self.hashPrevBlock))
            return False 


        # Check timestamp against prev
        if self.GetHash("hex").encode() != ctx.hashGenesisBlock and self.nTime <= ctx.mapBlockIndex[self.hashPrevBlock].nTime:
            logg("AcceptBlock() - block's timestamp is too early".format(self.hashPrevBlock))
            return False 

        if self.GetHash("hex").encode() != ctx.hashGenesisBlock and self.nBits != GetNextWorkRequired():
            logg("AcceptBlock() - block incorrect proof of work")
            return False

        if not self.CheckBlock(pnode):
            return False


    
        # update memory 
        ctx.mapBlockIndex[self.GetHash()] = self
        ctx.bestHash = self.GetHash()
        ctx.bestHeight +=1
        ctx.height_map[self.GetHash()] = ctx.bestHeight
        ctx.mapHeight[ctx.bestHeight] = self



        if BlocksDB().WriteBlock(self):
            for tx in self.nTxs:
                if BlocksDB().WriteTxIndex(tx.GetHash(), tx.nValue, 0):
                    if not tx.IsCoinBase():
                        

                        # does the input tx has enough coins ??
                        old = ctx.mapTxIndex[tx.nPrevTx]
                        # total received 
                        total_received = old[0] 
                        # total spend
                        total_spend = old[1]  


                        # delete the nPrevTx from mapTxIndex memory 
                        del ctx.mapTxIndex[tx.nPrevTx]
                        # update the mapTxIndex memoryu with the new changes 
                        ctx.mapTxIndex[tx.nPrevTx] = (total_received, int(total_spend) + tx.nValue) 


                        # update chances for output on local memory
                        ctx.mapTxIndex[tx.GetHash()] = (tx.nValue, 0)

                        # Add transaction to blockchain transactions map
                        ctx.mapTransactions[tx.GetHash()]  = tx


                        if tx.IsMine():
                            # This is a loose transaction and we are the reciptiens 
                            # Add transaction to our wallet transactions map 
                            ctx.mapWalletTransactions[tx.GetHash()] = tx



                        # update chances on database

                        with ctx._env.begin(write=True, db=ctx._blocks_db) as txn:
                            key = b"txindex:" + str(tx.nPrevTx).encode()
                            value = b"received:" + str(total_received).encode() + b":spend:" + str(int(total_spend) + tx.nValue).encode()
                            if txn.delete(key):
                                if not txn.put(key, value):
                                    return False
                                        
                    else:
                        if tx.IsCoinBase():
                            if tx.IsMine():
                                # This is a coinbase transaction inluded in a block that we mint 
                                # Add transaction to our wallet transactions map 
                                ctx.mapWalletTransactions[tx.GetHash()] = tx
                                # Add transaction to blockchain transactions map
                                ctx.mapTransactions[tx.GetHash()]  = tx
                            
                            # As it is a coinbase tx, there is no spend only input..
                            # Add transaction to mapTxIndex, no matter if is our or not.
                            ctx.mapTxIndex[tx.GetHash()] = (tx.nValue, 0)   
                            # Add transaction to blockchain transactions map
                            ctx.mapTransactions[tx.GetHash()]  = tx                  
                else:
                    return False 


        for tx in self.nTxs:
            # remove transactions from mempool.
            if tx in ctx.memPool:
                ctx.memPool.remove(tx)


        return True
