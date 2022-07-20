import logging 
import sys
from os.path import expanduser
from sys import platform
import binascii
import hashlib

from app import context as ctx
from app.block import consensus

import struct

bchr = chr
if sys.version > '3':
    bchr = lambda x: bytes([x])


logging.basicConfig(level=logging.INFO, filename="debug.log", format='%(asctime)s %(message)s') # include timestamp


hexlify = binascii.hexlify  
unhexlify = binascii.unhexlify


def logg(msg): 
    logging.info(msg)



def GetAppDir():
    # currently suppports linux 
    if not platform == "linux":
        if not platform == "linux2":
            sys.exit(logg("Error: Unsupported platform"))
    return expanduser("~") + "/" + ".stater"


def Hash(s, s2=None, s3=None, out_type=None):
    if s2 is not None:
        s += s2
    if s3 is not None:
        s += s3
    h = hashlib.sha256(hashlib.sha256(s).digest())
    if out_type == 'hex':
        return h.hexdigest()
    digest = h.digest()
    if out_type == 'str':
        return digest
    return deser_uint256(digest)



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
        y = bits2target(GetNextWorkRequired(plog=False))
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

def GetNextWorkRequired(plog=True):

    # latest block hash 
    pindexLast = ctx.bestHash
    
    # 10 minutes 
    nTargetTimespan =  600
    # We need 5 minutes between each block  
    nTargetSpacing = 300
    # Difficulty chances every 2 blocks
    nInterval = nTargetTimespan / nTargetSpacing


    
    # The above sets give as 2 blocks every 10 minutes, or 1 block every 5 minutes 
    # If thhose 2 blocks took les than 10 minutes to be minting difficulty goes up
    # if thoose 2 blocks took more than 10 minutes to be minting difficulty goes down.


    
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
    if plog:
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

    if plog:
        logg("\n\n\nGetNextWorkRequired RETARGET *****\n")
        logg("nTargetTimespan = {}    nActualTimespan = {}\n".format(nTargetTimespan, nActualTimespan))
        logg("Last {} blocks time average was {}\n".format(nInterval, nActualTimespan))
        logg("Before: %08x  %s\n" %(ctx.mapBlockIndex[ctx.bestHash].nBits, nActualTimespan,))
        logg("After:  %08x  %s\n" %(GetCompact(int(bnNew)), nActualTimespan,))

    return GetCompact(int(bnNew))
