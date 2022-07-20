#!/usr/bin/python
# Copyright (c) 2022 Papa Crouz
# Distributed under the MIT/X11 software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.


from app import context as ctx
from app.block import consensus


def GetBlockValue(height, fees=0):
    subsidy = consensus.nCoin * consensus.COIN
    return subsidy + fees


