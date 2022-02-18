# ----------------------------------------
## Create keys
# ----------------------------------------

from reference_implementations.schnorr_signatures.reference import *

# Create random 256-bit secret that is later turned into a private key
def create_random_secret() -> bytes:
    import random
    random_secret = (random.getrandbits(256)).to_bytes(32, byteorder="big", signed=False)
    if not (1 <= int_from_bytes(random_secret) <= n - 1):
        raise ValueError('The random_secret must be an integer in the range 1..n-1.')
    return random_secret

# Determine private-public key pair (32-byte public key --> only x-coordinate) from secret so that only even y-values of public key occur
def determine_private_public_key_pair(secret: bytes) -> Tuple[bytes, bytes]:
    secret_int = int_from_bytes(secret)
    public_key_point = point_mul(G, secret_int)
    assert public_key_point is not None
    if has_even_y(public_key_point):
        private_key = secret  
    else:
        private_key = bytes_from_int((n - secret_int))
    public_key = pubkey_gen(secret)
    return (private_key, public_key)


# ----------------------------------------
## Create bech32m address for testnet
# ----------------------------------------

def create_bech32m_address(public_key):
    from reference_implementations.bech32m_addresses.segwit_addr import encode
    bech32m_address = encode('tb', 1, public_key) # last argument is witness version
    return bech32m_address


# ----------------------------------------
## Write private key and address to file
# ----------------------------------------

def write_address_and_key_to_file(bech32m_address: str, private_key: bytes):   
    
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
        keys.writerow([bech32m_address, private_key.hex()])
    print('Writing address and key to CSV file was successful')