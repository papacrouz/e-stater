from cryptos import *
import uuid

from app import context as ctx
from app.db.db import CWalletDB


# generate keys lib, this should be replaced. 
Ckey = Bitcoin(testnet=False)


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