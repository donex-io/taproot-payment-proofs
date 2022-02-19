# ----------------------------------------
## Bitcoin RPC stuff
# ----------------------------------------

# load bitcoin-rpc library, https://github.com/jgarzik/python-bitcoinrpc (sudo pip install python-bitcoinrpc)
from bitcoinrpc.authproxy import AuthServiceProxy, JSONRPCException

# setup JSON-rpc connection with bitcoind, credentials are set in bitcoin.conf
bt_cli = AuthServiceProxy("http://%s:%s@127.0.0.1:18332"%('admin', 'admin'), timeout=120)


# ----------------------------------------
## Import functions
# ----------------------------------------

import sys
import os

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.append(os.path.dirname(SCRIPT_DIR))

from scan_utxo_set import *


# ----------------------------------------
## Program
# ----------------------------------------

address = 'tb1pq0vkpu8qy5x60rp0cg2j28f85dlw6jaq5ef6atkul49n08ntav4qdd0lye'

print('\n',f"Start scanning for address: {address}", '\n')
print(start_scanutxos(bt_cli, address))


# ----------------------------------------
## Async tests (not succesful yet)
# ----------------------------------------

# functions called would have to be adapted to async for this!
# import asyncio
# loop = asyncio.get_event_loop()
# try: 
#     # loop.create_task(query_status_scanutxos()) # not working at the moment
#     future = loop.create_task(start_scanutxos(bt_cli, address))  
#     loop.run_until_complete(future)
# except KeyboardInterrupt:
#     pass
# finally: 
#     loop.close()