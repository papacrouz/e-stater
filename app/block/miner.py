#!/usr/bin/python
# Copyright (c) 2022 Papa Crouz
# Distributed under the MIT/X11 software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.



from app import context as ctx
from app.block.block import Block
from app.block.tx.tx import Transaction
from app.block.util import GetBlockValue
from app.utils.baseutil import unhexlify
from app.block.key.action import GenerateNewKey
from app.utils.baseutil import GetNextWorkRequired, bits2target
from app.utils.baseutil import logg


import time

def StaterMiner(t, msg=None):

    logg("Stater started")
    
    if msg:
        logg(msg)

    key = GenerateNewKey()


    while True:
        t.check_self_shutdown()
        if t.exit:
            break



        tx = Transaction()
        tx.nValue = GetBlockValue(ctx.bestHeight)
        tx.nTo = unhexlify(key)



        pblock = Block()
        pblock.hashPrevBlock = ctx.bestHash


        # add our coinbase tx into block 
        pblock.nTxs.append(tx)


        # add rest of txs, if exists 
        for tx in ctx.memPool:
            pblock.nTxs.append(tx)

        pblock.hashMerkleRoot = pblock.BuildMerkleTree()
        pblock.nTime = int(time.time())
        pblock.nBits = GetNextWorkRequired()
        pblock.nNonce = 0

        target = (pblock.nBits & 0xffffff) * 2**(8*((pblock.nBits >> 24) - 3))


        p = bits2target(0x1e0fffff)
        y = bits2target(GetNextWorkRequired())


        logg("Running miner with {} transactions in block".format(len(pblock.nTxs)))



        while True:
            t.check_self_shutdown()
            if t.exit:
                logg("Miner got an exit signal")
                break
                
            if pblock.hashPrevBlock != ctx.bestHash:
                # Job Work change we should restart our miner here.
                # Someone else miner have minting succesfully the block.
                StaterMiner(t, msg="Miner restarted, new block detected on network")
                break

            if int(pblock.GetHash(out_type="hex", header=True), 16) <= target:
                logg("Block {} found with dificulty {}".format(pblock.GetHash("hex"), int(p/y)))
                if pblock.AcceptBlock(pnode=False):
                    ctx.readForRelayBlocks.append(pblock.serialize())
                    logg("Block {} accepted".format(pblock.GetHash("hex")))
                return True 
            pblock.nNonce +=1



