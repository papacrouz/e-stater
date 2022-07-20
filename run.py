#!/usr/bin/env python
# -*- coding: utf-8 -*-




import tkinter as tk

from tkinter import *


import traceback
import app.block.action as blockaction
import app.net.action as networkaction
from app.ui.main import Stater



print ("Loading wallet & keys...")
if not blockaction.loadWallet():
    ctx.err += "Error loading wallet and addresses\n"

print("Loading block index...")

if not blockaction.loadBlockIndex():
	ctx.err += "Error loading blockchain\n"


if not networkaction.startNode(client=False, server=True):
	ctx.err += "Error starting node\n"



print ("Done loading")


if __name__ == "__main__":

   
    root = Tk()
    root.geometry("655x330+350+100")
    Stater(root=root)
    root.title("Stater Client")
    root.mainloop()
