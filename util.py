import logging 
import sys
from os.path import expanduser
from sys import platform
import binascii


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



