print('\n')

# ----------------------------------------
## Create keys
# ----------------------------------------

# Create randomized private key

import random

private_key = (random.getrandbits(256)).to_bytes(32, byteorder="little", signed=False)
print(f'private_key                  =   {private_key.hex()}', '\n')


# Create public key data in different formats (we eventually need the compressed public key)

from reference_implementations.schnorr_signatures.reference import bytes_from_int, x, y, pubkey_gen, lift_x

x_coordinate = pubkey_gen(private_key)
print(f'x_coordinate                 =   {x_coordinate.hex()}', '\n')

pubkey_point = lift_x(x_coordinate)

x_coordinate = bytes_from_int(x(pubkey_point)).hex()
y_coordinate = bytes_from_int(y(pubkey_point)).hex()

print(f'x_coordinate                 =   {x_coordinate}', '\n')
print(f'y_coordinate                 =   {y_coordinate}', '\n')

if y(pubkey_point) % 2 == 0:
    compressed_public_key = bytes.fromhex(f'02{x_coordinate}')
else: 
    compressed_public_key = bytes.fromhex(f'03{x_coordinate}')

print(f'compressed_public_key        = {compressed_public_key.hex()}', '\n')


# create hashed public key

import hashlib

hashed_compressed_public_key = hashlib.sha256(compressed_public_key).digest()
print(f'hashed_compressed_public_key =   {hashed_compressed_public_key.hex()}', '\n')



# ----------------------------------------
## Create bech32m address for testnet
# ----------------------------------------

# bech32_encode(hrp, data, spec) for testnet address hrp = 'tb' , data = sha256(compressed_public_key) , spec = 2 (bech32m)

from reference_implementations.bech32m_addresses.segwit_addr import encode

bech32m_address = encode('tb', 1, hashed_compressed_public_key)
print(f'bech32m_address              =   {bech32m_address}', '\n')


# ----------------------------------------
## Write private key and address to file
# ----------------------------------------

# Determine file path

import os

script_dir = os.path.dirname(__file__)
rel_path = "create_keys_and_addresses/keys_and_addresses.csv"
abs_file_path = os.path.join(script_dir, rel_path)


# Write to file

import csv

with open(abs_file_path, 'a', newline='') as csvfile:
    keys = csv.writer(csvfile, delimiter=' ',
                            quotechar='|', quoting=csv.QUOTE_MINIMAL)
    keys.writerow([bech32m_address, private_key.hex()])