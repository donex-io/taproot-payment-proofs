# ----------------------------------------
## Imports
# ----------------------------------------

import sys
import os

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.append(os.path.dirname(SCRIPT_DIR))

from features.reference_implementations.schnorr_signatures.reference import *

# ----------------------------------------
## Create keys
# ----------------------------------------

# Create random 256-bit secret that is later turned into a private key
def create_random_secret() -> bytes:
    import random
    while True:
        random_secret_32byte = (random.getrandbits(256)).to_bytes(32, byteorder="big", signed=False)
        if (1 <= int_from_bytes(random_secret_32byte) <= n - 1):
            return random_secret_32byte

# Determine private-public key pair (32-byte public key --> only x-coordinate) from secret so that only even y-values of public key occur
def determine_private_public_key_pair(secret_32byte: bytes) -> Tuple[bytes, bytes]:
    if len(secret_32byte) != 32:
         raise ValueError('The secret must be 32 bytes long.')
    secret_int = int_from_bytes(secret_32byte)
    public_key_point = point_mul(G, secret_int)
    assert public_key_point is not None
    if has_even_y(public_key_point):
        private_key = secret_32byte  
    else:
        private_key = bytes_from_int((n - secret_int))
    public_key = bytes_from_point(public_key_point)
    return (private_key, public_key)


# ----------------------------------------
## Create bech32m address for testnet
# ----------------------------------------

def create_bech32m_taproot_address(public_key, network):
    from reference_implementations.bech32m_addresses.segwit_addr import encode   
    if network == "testnet":
        bech32m_address = encode('tb', 1, public_key) # arguments: network, witness_version, public_key
    elif network == "mainnet":
        bech32m_address = encode('bc', 1, public_key) # arguments: network, witness_version, public_key
    return bech32m_address


# ----------------------------------------
## Write private key and address to file
# ----------------------------------------

def write_address_and_key_to_file(bech32m_address: str, private_key: bytes, public_key: bytes):   
    
    # Determine file path
    import os
    script_dir = os.path.dirname(__file__)
    rel_path = "create_keys_and_addresses/keys_and_addresses.csv"
    abs_file_path = os.path.join(script_dir, rel_path)
    
    # Determine file path
    import csv
    with open(abs_file_path, 'a', newline='') as csvfile:
        keys = csv.writer(csvfile, delimiter=' ',
                                quotechar='|', quoting=csv.QUOTE_MINIMAL)
        keys.writerow([bech32m_address, private_key.hex(), public_key.hex()])
    print('Writing address and key to CSV file was successful')