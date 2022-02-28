# Start only once in the beginning to initalize the program in the cloud:
#!curl -o- -s -S -L https://raw.githubusercontent.com/bitcoinops/taproot-workshop/Colab/setup-colab-env.sh | bash


# Key pair generation
privkey, pubkey = generate_bip340_key_pair()
# print("Pubkey is {}\n".format(pubkey.get_bytes().hex()))

# Create witness program ([32B x-coordinate])
program = pubkey.get_bytes()
# print("Witness program is {}\n".format(program.hex()))

# Create (regtest) bech32m address
version = 0x01
address = program_to_witness(version, program)
# print("bech32m address is {}".format(address))

# Generate the taproot signature hash for signing
# SIGHASH_ALL_TAPROOT is 0x00

import binascii
import hashlib
import itertools
import queue
import struct

import util
from test_framework.address import *
from test_framework.key import *
from test_framework.messages import *
from test_framework.musig import *
from test_framework.script import *

from binascii import unhexlify
spending_tx = CTransaction()
tx = CTransaction()
from io import BytesIO

# Spending TX (with has to be signed):
raw_spending_tx_hex = '01000000000101d1f1c1f8cdf6759167b90f52c9ad358a369f95284e841d7a2536cef31c0549580100000000fdffffff020000000000000000316a2f49206c696b65205363686e6f7272207369677320616e6420492063616e6e6f74206c69652e204062697462756734329e06010000000000225120a37c3903c8d0db6512e2b40b0dffa05e5a3ab73603ce8c9c4b7771e5412328f90140a60c383f71bac0ec919b1d7dbc3eb72dd56e7aa99583615564f9f99b8ae4e837b758773a5b2e4c51348854c8389f008e05029db7f464a5ff2e01d5e6e626174affd30a00'
spending_tx.deserialize(BytesIO(bytes.fromhex(raw_spending_tx_hex)))

# Spending from TX:
raw_tx = '01000000000101b9cb0da76784960e000d63f0453221aeeb6df97f2119d35c3051065bc9881eab0000000000fdffffff020000000000000000186a16546170726f6f74204654572120406269746275673432a059010000000000225120339ce7e165e67d93adb3fef88a6d4beed33f01fa876f05a225242b82a631abc00247304402204bf50f2fea3a2fbf4db8f0de602d9f41665fe153840c1b6f17c0c0abefa42f0b0220631fe0968b166b00cb3027c8817f50ce8353e9d5de43c29348b75b6600f231fc012102b14f0e661960252f8f37486e7fe27431c9f94627a617da66ca9678e6a2218ce1ffd30a00'
tx.deserialize(BytesIO(bytes.fromhex(raw_tx)))
#print([tx.vout[1]])


MAX_SCRIPT_ELEMENT_SIZE = 520
LOCKTIME_THRESHOLD = 500000000
ANNEX_TAG = 0x50

OPCODE_NAMES = {}

LEAF_VERSION_TAPSCRIPT = 0xc0

DEFAULT_TAPSCRIPT_VER = 0xc0
TAPROOT_VER = 0

SIGHASH_ALL_TAPROOT = 0
SIGHASH_ALL = 1
SIGHASH_NONE = 2
SIGHASH_SINGLE = 3
SIGHASH_ANYONECANPAY = 0x80

def TaprootSignatureHash(txTo, spent_utxos, hash_type, input_index = 0, scriptpath = False, script = CScript(), codeseparator_pos = -1, annex = None, leaf_ver = LEAF_VERSION_TAPSCRIPT):
    assert (len(txTo.vin) == len(spent_utxos))
    assert (input_index < len(txTo.vin))
    out_type = SIGHASH_ALL if hash_type == 0 else hash_type & 3
    in_type = hash_type & SIGHASH_ANYONECANPAY
    spk = spent_utxos[input_index].scriptPubKey
    ss = bytes([0, hash_type]) # epoch, hash_type
    ss += struct.pack("<i", txTo.nVersion)
    ss += struct.pack("<I", txTo.nLockTime)
    if in_type != SIGHASH_ANYONECANPAY:
        ss += sha256(b"".join(i.prevout.serialize() for i in txTo.vin))
        ss += sha256(b"".join(struct.pack("<q", u.nValue) for u in spent_utxos))
        ss += sha256(b"".join(ser_string(u.scriptPubKey) for u in spent_utxos))
        ss += sha256(b"".join(struct.pack("<I", i.nSequence) for i in txTo.vin))
    if out_type == SIGHASH_ALL:
        ss += sha256(b"".join(o.serialize() for o in txTo.vout))
        print(b"".join(o.serialize() for o in txTo.vout).hex())
    spend_type = 0
    if annex is not None:
        spend_type |= 1
    if (scriptpath):
        spend_type |= 2
    ss += bytes([spend_type])
    if in_type == SIGHASH_ANYONECANPAY:
        ss += txTo.vin[input_index].prevout.serialize()
        ss += struct.pack("<q", spent_utxos[input_index].nValue)
        ss += ser_string(spk)
        ss += struct.pack("<I", txTo.vin[input_index].nSequence)
    else:
        ss += struct.pack("<I", input_index)
    if (spend_type & 1):
        ss += sha256(ser_string(annex))
    if out_type == SIGHASH_SINGLE:
        if input_index < len(txTo.vout):
            ss += sha256(txTo.vout[input_index].serialize())
        else:
            ss += bytes(0 for _ in range(32))
    if (scriptpath):
        ss += tagged_hash("TapLeaf", bytes([leaf_ver]) + ser_string(script))
        ss += bytes([0])
        ss += struct.pack("<i", codeseparator_pos)
    assert len(ss) ==  175 - (in_type == SIGHASH_ANYONECANPAY) * 49 - (out_type != SIGHASH_ALL and out_type != SIGHASH_SINGLE) * 32 + (annex is not None) * 32 + scriptpath * 37
    
    print(">> Preimage: ", ss.hex())
    print(">> Final hash: ", tagged_hash("TapSighash", ss).hex())
    return tagged_hash("TapSighash", ss)

sighash = TaprootSignatureHash(spending_tx, [tx.vout[1]], SIGHASH_ALL_TAPROOT, input_index=0)
 
# All schnorr sighashes except SIGHASH_ALL_TAPROOT require
# the hash_type appended to the end of signature
sig = privkey.sign_schnorr(sighash)

#print("\n")
#print("Pubkey is {}\n".format(pubkey.get_bytes().hex()))
#print("Sighash is {}\n".format(sighash.hex()))
#print("Signature: {}\n".format(sig.hex()))