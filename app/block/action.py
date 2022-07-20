#!/usr/bin/python
# Copyright (c) 2022 Papa Crouz
# Distributed under the MIT/X11 software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.


from app import context as ctx
from app.block.block import Block
from app.block.tx.tx import Transaction
from app.utils.serdeser import uint256_from_str
from app.utils.baseutil import logg, unhexlify
from app.db.db import CsignaturesDB
import io



def loadWallet():
    with ctx._env.begin() as txn:
        for key, value in txn.cursor(db=ctx._wallet_db):
            ptr = key.split(b":")
            if ptr[0] == b"key": ctx.mapKeys[ptr[1]] = value
            if ptr[0] == b"tx":
                tx = Transaction()
                tx.deserialize(io.BytesIO(value))
                ctx.mapWalletTransactions[uint256_from_str(ptr[1])] = tx
        return True



def loadBlockIndex():
    logg("Loading BlockIndex")
    with ctx._env.begin() as txn:
        for key, value in txn.cursor(db=ctx._blocks_db).iterprev():
            ptr = key.split(b":")
            ptr_value = value.split(b":")
            if ptr[0] == b"block":
                block = Block()
                block.deserialize(value)

                # map block 
                ctx.mapBlockIndex[uint256_from_str(ptr[1])] = block
                ctx.bestHash = uint256_from_str(ptr[1])
                ctx.bestHeight +=1
                ctx.mapHeight[ctx.bestHeight] = block
                ctx.height_map[uint256_from_str(ptr[1])] = ctx.bestHeight

                # map transactions 
                for tx in block.nTxs:
                    tx.nSignature = CsignaturesDB().ReadSignature(tx.GetHash())
                    ctx.mapTransactions[tx.GetHash()] = tx 

            if ptr[0] == b"txindex":
                txHash = uint256_from_str(ptr[1])
                txReceived = ptr_value[1]
                txSpend = ptr_value[3]

                if txReceived.count(b'b'):
                    txReceived = txReceived[2: len(txReceived) -1]


                ctx.mapTxIndex[txHash] = (txReceived, txSpend)



                


        if len(ctx.mapBlockIndex) == 0:
            key = "04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5f"


            genesisTx = Transaction()
            genesisTx.nValue = 50 * 100000000
            genesisTx.nTo = unhexlify(key)



            genesisBlock = Block()
            genesisBlock.hashPrevBlock = 0 

            # add our coinbase tx into block 
            genesisBlock.nTxs.append(genesisTx)


            genesisBlock.hashMerkleRoot = genesisBlock.BuildMerkleTree()
            genesisBlock.nTime = 1657921559
            genesisBlock.nBits = 0x1e0fffff
            genesisBlock.nNonce = 198589




            """
            target = (genesisBlock.nBits & 0xffffff) * 2**(8*((genesisBlock.nBits >> 24) - 3))

            while True:
                if int(genesisBlock.GetHash(out_type="hex", header=True), 16) <= target:
                    genesisBlock.Print()
                    print(genesisBlock.GetHash("hex"))
                    break 
                genesisBlock.nNonce +=1
            """

            """ 
            Block(hash=b'00000f9ab97717c5d1101811f9a805534436048aa88a5bb7e1bf9c854b4fee44', 
            ver=1, hashPrevBlock=b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00', 
            hashMerkleRoot=b'3536306336633234623062346233323733306238373863366438306135616133', 
            nTime=1657921559, nBits=504365055, nNonce=198589, vtx=1)
            """









            assert(genesisBlock.GetHash("hex") == "00000f9ab97717c5d1101811f9a805534436048aa88a5bb7e1bf9c854b4fee44")

            if not genesisBlock.AcceptBlock():
                logg("loadBlockIndex() - Add genesis to database failed.")
                return False
            else:
                logg("loadBlockIndex() - Genesis block added to database.")

    

        return True