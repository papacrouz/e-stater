#!/usr/bin/python
# Copyright (c) 2022 Papa Crouz
# Distributed under the MIT/X11 software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

import struct, io, hashlib
import traceback
from io import StringIO
from cryptos import *
import types
# Py3 compatibility
import sys
import uuid
import context as ctx
import consensus
import threading
from signal import signal, SIGINT

from serdeser import *

import ecdsa

from util import logg, hexlify, unhexlify


import _thread


# generate keys lib, this should be replaced. 
Ckey = Bitcoin(testnet=False)




def GetBlockValue(height, fees=0):
    subsidy = consensus.nCoin * consensus.COIN
    return subsidy + fees



def handler(signal_received, frame):
    # Handle any cleanup here
    ctx.fShutdown = True


def check_for_shutdown(t):
    # handle shutdown 
    n = t.n
    if ctx.fShutdown:
        if n != -1:
            ctx.listfThreadRunning[n] = False
            t.exit = True



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



    def loadWallet(self):
        with ctx._env.begin() as txn:
            for key, value in txn.cursor(db=ctx._wallet_db):
                ptr = key.split(b":")
                if ptr[0] == b"key": ctx.mapKeys[ptr[1]] = value
                if ptr[0] == b"tx":
                    tx = Transaction()
                    tx.deserialize(io.BytesIO(value))
                    ctx.mapWalletTransactions[uint256_from_str(ptr[1])] = tx
        return True





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
        key = b"txindex:" + txhash.encode()
        value = b"received:" + str(received).encode() + b":spend:" + str(spend).encode()
        return self.Write(key, value)



    def loadBlockIndex(self):
        ret = 0
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







def AddKey(pub, priv):
    # add to map 
    with ctx.mapKeysLock:
        ctx.mapKeys[pub.encode()] = priv.encode()
    
    return CWalletDB().WriteKey(pub, priv)


def GenerateNewKey():
    priv = sha256(uuid.uuid4().hex)
    pub = Ckey.privtopub(priv)

    if not AddKey(pub, priv):
        logg("GenerateNewKey() - Add new key failed")
        return False 
    return pub 



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
        tx.nTo = to.encode()
        # get the input pubkey key owner 
        owner = ctx.mapTransactions[txindex].nTo
        # get the private key 
        privkey = ctx.mapKeys[hexlify(owner)]
        # import the priv key 
        sk = ecdsa.SigningKey.from_string(unhexlify(privkey), curve=ecdsa.SECP256k1)
        # sign the prev tx 
        signature = sk.sign(str(tx.GetHash()).encode())


        tx.nSignature = signature

        ctx.readForRelayTransactions.append(tx)

        return True 
    return False




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

        if self.IsMine():
            ret = CWalletDB().WriteTx(self)
            if ret:
                logg("Transaction {} added to wallet".format(self.GetHash("hex")))


        if not self.IsCoinBase():
            # check signature
            if self.nPrevTx not in ctx.mapTransactions:
                logg("CheckTransaction() - Prev tx {} not found")
                return False 


            owner = hexlify(ctx.mapTransactions[self.nPrevTx].nTo)
            vk = pubkey_to_verifykey(owner)

            
            # this transaction must be signed with the private key of the input tx hash 
            if not vk.verify(self.nSignature, str(self.GetHash()).encode()):
                logg("CheckTransaction() Verify signature for tx {} failed".format(self.GetHash("hex")))
                return False

        return True



def num2mpi(n):
    """convert number to MPI string"""
    if n == 0:
         return struct.pack(">I", 0)
    r = b""
    neg_flag = bool(n < 0)
    n = abs(n)
    while n:
        r = bchr(n & 0xFF) + r
        n >>= 8
    if r[0] & 0x80:
        r = bchr(0) + r
    if neg_flag:
        r = bchr(ord(r[0]) | 0x80) + r[1:]
    datasize = len(r)

    return struct.pack(">I", datasize) + r

def target2bits(target):
        MM = 256*256*256
        c = ("%064X"%int(target))[2:]
        i = 31
        while c[0:2]=="00":
            c = c[2:]
            i -= 1
        c = int('0x'+c[0:6],16)
        if c >= 0x800000:
            c //= 256
            i += 1
        new_bits = c + MM * i
        return new_bits


def bits2target(bits):
    """ Convert bits to target """
    exponent = ((bits >> 24) & 0xff)
    mantissa = bits & 0x7fffff
    if (bits & 0x800000) > 0:
        mantissa *= -1 
    return (mantissa * (256**(exponent-3)))


def CalculateDiff(nbits=None):
    """ Calculate current difficulty """
    # diff is minimun difficulty target / current_target 
    p = 0x00000000FFFF0000000000000000000000000000000000000000000000000000
    if not nbits:
        y = bits2target(GetNextWorkRequired())
    else:
        y = bits2target(nbits)
    return p / y


def GetCompact(n):
    """convert number to bc compact uint"""
    mpi = num2mpi(n)
    nSize = len(mpi) - 4
    nCompact = (nSize & 0xFF) << 24
    if nSize >= 1:
        nCompact |= (mpi[4] << 16)
    if nSize >= 2:
        nCompact |= (mpi[5] << 8)
    if nSize >= 3:
        nCompact |= (mpi[6] << 0)

    return nCompact


def GetNextWorkRequired():

    # latest block hash 
    pindexLast = ctx.bestHash

    # Difficulty will change every 600 seconds or 10 minuntes
    nTargetTimespan = 600

    # We need a new block every 4 seconds
    nTargetSpacing = 100

    # That give us a interval 6 blocks
    nInterval = nTargetTimespan / nTargetSpacing

    
    # if the last block height = 0 return the minimun diif
    if ctx.height_map[ctx.bestHash] == 0:
        return 0x1e0fffff

    # Only change once per interval
    if ((ctx.height_map[ctx.bestHash]+1) % nInterval != 0):
        # Return the last block bits (difficulty)
        return ctx.mapBlockIndex[ctx.bestHash].nBits


    # Go back by what we want to be 10 minuntes worth of blocks
    # nActualTimespan is the avg time of the last 6 blocks, example if each of the last 6 blocks took 30 seconds nActualTimespan will be 180
    nActualTimespan = ctx.mapBlockIndex[ctx.bestHash].nTime - ctx.mapHeight[int(ctx.height_map[ctx.bestHash] - nInterval +1)].nTime

    # so if the nActualTimespan is bigger the nTargetTimespan means that blocks are mined slowly, difficulty will be reduced,
    # if the nActualTimespan is lower than nTargetTimespan means that blocks are mined quick, difficulty will be increased

    logg("nActualTimespan = {}  before bounds\n".format(nActualTimespan))

    if nActualTimespan < nTargetTimespan/4:
        nActualTimespan = nTargetTimespan/4
    if nActualTimespan > nTargetTimespan*4:
        nActualTimespan = nTargetTimespan*4


    bnNew = bits2target(ctx.mapBlockIndex[ctx.bestHash].nBits)
    bnNew *= nActualTimespan
    bnNew /= nTargetTimespan

    if bnNew > consensus.bnProofOfWorkLimit:
        bnNew = consensus.bnProofOfWorkLimit

    

    logg("\n\n\nGetNextWorkRequired RETARGET *****\n")
    logg("nTargetTimespan = {}    nActualTimespan = {}\n".format(nTargetTimespan, nActualTimespan))
    logg("Last {} blocks time average was {}\n".format(nInterval, nActualTimespan))
    logg("Before: %08x  %s\n" %(ctx.mapBlockIndex[ctx.bestHash].nBits, nActualTimespan,))
    logg("After:  %08x  %s\n" %(GetCompact(int(bnNew)), nActualTimespan,))

    return GetCompact(int(bnNew))








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
                if BlocksDB().WriteTxIndex(tx.GetHash("hex"), tx.nValue, 0):
                    if not tx.IsCoinBase():
                        # This is a looose transaction, a loose tx is a tx between 2 parties 
                        # update chances on local memory 
                        old = ctx.mapTxIndex[tx.nPrevTx]
                        del ctx.mapTxIndex[tx.nPrevTx]
                        ctx.mapTxIndex[tx.nPrevTx] = (old[0], int(old[0]) - tx.nValue) 
                        # update chances on database 
                        prevTxIndex = unhexlify(hexser_uint256(tx.nPrevTx))

                        with ctx._env.begin() as txn:
                            for key, value in txn.cursor(db=ctx._blocks_db).iterprev():
                                ptr = key.split(b":")
                                ptr_value = value.split(b":")

                                if ptr[0] == b"txindex":
                                    txHash = ptr[1]
                                    if txHash.startswith(prevTxIndex):
                                        # delete this 
                                        with ctx._env.begin(write=True, db=ctx._blocks_db) as txn:
                                            key = b"txindex:" + txHash
                                            value = b"received:" + str(old[0]).encode() + b":spend:" + str(int(old[0]) - tx.nValue).encode()
                                            if txn.delete(key):
                                                if not txn.put(key, value):
                                                    return False
                    else:
                        if tx.IsCoinBase():
                            if tx.IsMine():
                                # update wallet mem only with our coinbase txs 
                                ctx.mapWalletTransactions[tx.GetHash()] = tx
                            
                            # map 0 as spend its coinbase 
                            ctx.mapTxIndex[tx.GetHash()] = (tx.nValue, 0)   
                            ctx.mapTransactions[tx.GetHash()]  = tx                       
                else:
                    return False 


        return True







def StaterMiner(t):

    logg("Stater started")

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
        for tx in ctx.readForRelayTransactions:
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

            if int(pblock.GetHash(out_type="hex", header=True), 16) <= target:
                logg("Block {} found with dificulty {}".format(pblock.GetHash("hex"), int(p/y)))
                if pblock.AcceptBlock(pnode=False):
                    ctx.readForRelayBlocks.append(pblock.serialize())
                    logg("Block {} accepted".format(pblock.GetHash("hex")))
                return True 
            pblock.nNonce +=1







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




def pubkey_to_verifykey(pub_key, curve=ecdsa.SECP256k1):
    vk_string = unhexlify(pub_key[2:])
    return ecdsa.VerifyingKey.from_string(vk_string, curve=curve)



def StartMining():

    ctx._miner_t = CoinMinerThread(None)
    ctx._miner_t.start()
    logg("[*] Starer miner thread started")





def loadIndexes():
    if not BlocksDB().loadBlockIndex():
        return False

    if not CWalletDB().loadWallet():
        return False 

    return True



if not loadIndexes():
    sys.exit(logg("Error() Unable to load indexes."))

signal(SIGINT, handler)

