#!/usr/bin/python
# Original Author : https://github.com/benediktkr at /ncpoc
# Modified by CVSC

import hmac
import json

import os
import hashlib

def generate_nodeid():
    return hashlib.sha256(os.urandom(256)).hexdigest()

# generate_nodeid() uses SHA256 so this will prevent replay-attacks,
# because every message will have a different nonce.
# It's not nessecary to compare the nonce, HMAC already gives message
# integrety.


nonce = lambda: generate_nodeid()
incr_nonce = lambda env: format(int(env["nonce"], 16) + 1, 'x')

class InvalidSignatureError(Exception):
    pass

class InvalidNonceError(Exception):
    pass

def make_envelope(msgtype, msg, nodeid):
    msg['nodeid'] = nodeid
    msg['nonce'] =  nonce()
    data = json.dumps(msg)
    sign = hmac.new(nodeid.encode(), data.encode(), hashlib.sha256)
    envelope = {'data': msg,
                'sign': sign.hexdigest(),
                'msgtype': msgtype}
    #print "make_envelope:", envelope
    return json.dumps(envelope)

def envelope_decorator(nodeid, func):
    msgtype = func.__name__.split("_")[0]
    def inner(*args, **kwargs):
        return make_envelope(msgtype, func(*args, **kwargs), nodeid)
    return inner

# ------

def create_ackhello(nodeid):
    msg = {}
    return make_envelope("ackhello", msg, nodeid)

def create_hello(nodeid, version, protoversion):
    msg = {'version': version, 'protocol': protoversion}
    return make_envelope("hello", msg, nodeid)


def create_ping(nodeid):
    msg = {}
    return make_envelope("ping", msg, nodeid)

def create_pong(nodeid):
    msg = {}
    return make_envelope("pong", msg, nodeid)


def create_sync(nodeid, bestheight, besthash):
    msg = {'bestheight': bestheight, 'besthash':besthash}
    return make_envelope("sync", msg, nodeid)

def create_ask_blocks(nodeid, besthash):
    msg = {'besthash': besthash}
    return make_envelope("givemeblocks", msg, nodeid)


def create_send_block(nodeid, raw, signatures):
    msg = {'raw': raw, 'signatures': signatures}
    return make_envelope("getblock", msg, nodeid)

def create_sync_op(nodeid, bestheight, besthash):
    msg = {'bestheight': bestheight, 'besthash':besthash}
    return make_envelope("sync_op", msg, nodeid)

def create_relay_txs(nodeid, nodes):
    msg = {'txs': nodes}
    return make_envelope("relay_txs", msg, nodeid)


def create_getaddr(nodeid):
    msg = {}
    return make_envelope("getaddr", msg, nodeid)

def create_addr(nodeid, nodes):
    msg = {'nodes': nodes}
    return make_envelope("addr", msg, nodeid)
# -------

def read_envelope(message):
    return json.loads(message)

def read_message(message):
    """Read and parse the message into json. Validate the signature
    and return envelope['data']
    """
    envelope = json.loads(message)
    nodeid = str(envelope['data']['nodeid'])
    signature = str(envelope['sign'])
    msg = json.dumps(envelope['data'])
    verify_sign = hmac.new(nodeid.encode(), msg.encode(), hashlib.sha256)
    #print "read_message:", msg
    return envelope['data']

