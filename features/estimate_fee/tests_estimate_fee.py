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

from estimate_fee import *

# ----------------------------------------
## Test program
# ----------------------------------------

estimated_fee_per_vSize = estimate_fee_per_vSize(bt_cli, 10)

tx_fee = calculate_tx_fee(666, estimated_fee_per_vSize)

print(tx_fee)
