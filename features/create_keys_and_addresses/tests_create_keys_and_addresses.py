
# ----------------------------------------
## Run functions from file located above / create bech32m-Taproot-addresses from random keys / write into CSV file
# ----------------------------------------

import sys
import os

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.append(os.path.dirname(SCRIPT_DIR))

from create_keys_and_addresses import *

random_secret = create_random_secret()
[private_key, public_key] = determine_private_public_key_pair(random_secret)
test_public_key = pubkey_gen(private_key)
bech32m_address = create_bech32m_taproot_address(public_key, "testnet")

print('\n')

write_address_and_key_to_file(bech32m_address, private_key)

print('\n')
print(f'random_secret                =   {random_secret.hex()}', '\n')
print(f'private_key                  =   {private_key.hex()}', '\n')
print(f'public_key                   =   {public_key.hex()}', '\n')
print(f'test_public_key              =   {test_public_key.hex()}', '\n')
print(f'bech32m_address              =   {bech32m_address}', '\n')
print('\n')