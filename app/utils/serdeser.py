import struct, io, hashlib
import binascii
from io import StringIO
from cryptos import *
import types
import sys


bchr = chr
if sys.version > '3':
    bchr = lambda x: bytes([x])


def deser_int64(f): 
    return struct.unpack(b"<q", f.read(8))[0]


def ser_int64(u): 
    return struct.pack(b"<q", u)

    
def deser_str(f):
    nit = struct.unpack(b"<B", f.read(1))[0]
    if nit == 253:
        nit = struct.unpack(b"<H", f.read(2))[0]
    elif nit == 254:
        nit = struct.unpack(b"<I", f.read(4))[0]
    elif nit == 255:
        nit = struct.unpack(b"<Q", f.read(8))[0]
    return f.read(nit)


def ser_str(s):
    if len(s) < 253: return bchr(len(s)) + s
    elif len(s) < 254: return bchr(253) + struct.pack(b"<H", len(s)) + s
    elif len(s) < 255: return bchr(254) + struct.pack(b"<I", len(s)) + s
    return bchr(255) + struct.pack(b"<Q", len(s)) + s


def ser_uint256(u):
    rs = b""
    for i in range(8):
        rs += struct.pack(b"<I", u & 0xFFFFFFFF)
        u >>= 32
    return rs


def deser_uint256(f):
    r = 0
    if type(f) is str:
        f = io.BytesIO(f.encode())
    for i in range(8):
        t = struct.unpack(b"<I", f.read(4))[0]
        r += t << (i * 32)
    return r


def uint256_from_str(s):
    r = 0
    t = struct.unpack("<IIIIIIII", s[:32])
    for i in range(8):
        r += t[i] << (i * 32)
    return r

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

def hexser_uint256(u, in_type=None):
    if in_type != 'str':
        u = ser_uint256(u)
    return binascii.hexlify(u)  # ''.join(["%02X" % ord(x) for x in u])


def deser_uint(f, endian='small'):
    if endian == 'big':
        return struct.unpack(b">I", f.read(4))[0]
    return struct.unpack(b"<I", f.read(4))[0]


def ser_uint(i, endian='small'):
    if endian == 'big':
        return struct.pack(b">I", i)
    return struct.pack(b"<I", i)
def deser_int(f, endian='small'):
    if endian == 'big':
        return struct.unpack(b">i", f.read(4))[0]
    return struct.unpack(b"<i", f.read(4))[0]


def ser_int(i, endian='small'):
    if endian == 'big':
        return struct.pack(b">i", i)
    return struct.pack(b"<i", i)


def ser_list(l, ser_func=None, cls=None, nType=0, nVersion=1):
    s = io.BytesIO()
    if len(l) < 253:
        s.write(bchr(len(l)))
    elif len(l) < 254:
        s.write(bchr(253) + struct.pack(b"<H", len(l)))
    elif len(l) < 255:
        s.write(bchr(254) + struct.pack(b"<I", len(l)))
    else:
        s.write(bchr(255) + struct.pack(b"<Q", len(l)))
    for i in l:
        if cls is not None:
            s.write(cls.serialize(i))
        else:
            s.write(i.serialize() if ser_func is None else ser_func(i))
    return s.getvalue()


def deser_list(f, cls, arg1=None, nType=0, nVersion=1):
    nit = struct.unpack(b"<B", f.read(1))[0]
    if nit == 253:
        nit = struct.unpack(b"<H", f.read(2))[0]
    elif nit == 254:
        nit = struct.unpack(b"<I", f.read(4))[0]
    elif nit == 255:
        nit = struct.unpack(b"<Q", f.read(8))[0]
    r = []
    for i in range(nit):
        if isinstance(cls, types.FunctionType):
            t = cls(f)
        else:
            if arg1 is not None:
                t = cls(arg1)
            else:
                t = cls()
            t.deserialize(f)
        r.append(t)
    return r