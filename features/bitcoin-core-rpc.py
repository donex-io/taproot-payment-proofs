# load bitcoin-rpc library, https://github.com/jgarzik/python-bitcoinrpc (sudo pip install python-bitcoinrpc)
from bitcoinrpc.authproxy import AuthServiceProxy, JSONRPCException

# setup JSON-rpc connection with bitcoind, credentials are set in bitcoin.conf
bt_cli = AuthServiceProxy("http://%s:%s@127.0.0.1:18332"%('admin', 'admin'))

# test some RPC calls

    #print(bt_cli.getwalletinfo()['walletname'])
    #bt_cli.loadwallet(walletname)

print(bt_cli.getblockchaininfo())