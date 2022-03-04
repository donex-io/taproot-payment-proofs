import sys
import os
import json

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.append(os.path.dirname(SCRIPT_DIR))

from tx_builder import *

sys.path.insert(1, SCRIPT_DIR +'/bitcoinlib_package')
sys.path.insert(1, SCRIPT_DIR +'/ecdsa-0.10')
import bitcoinlib

PARENT_DIR = os.path.dirname(SCRIPT_DIR)
sys.path.insert(1, PARENT_DIR +'/reference_implementations/schnorr_signatures')
from reference import *

sys.path.insert(1, PARENT_DIR)
from schnorr_signature_with_data import *

# -------- Real world example --------


# Example https://blockstream.info/tx/37777defed8717c581b4c0509329550e344bdc14ac38f71fc050096887e535c8?expand

# NOTE: Pubkey would need to be provided by wallet again (has to be same as in previous TX output)
test_pubkey = '339ce7e165e67d93adb3fef88a6d4beed33f01fa876f05a225242b82a631abc0'

test_tx = '01000000000101d1f1c1f8cdf6759167b90f52c9ad358a369f95284e841d7a2536cef31c0549580100000000fdffffff020000000000000000316a2f49206c696b65205363686e6f7272207369677320616e6420492063616e6e6f74206c69652e204062697462756734329e06010000000000225120a37c3903c8d0db6512e2b40b0dffa05e5a3ab73603ce8c9c4b7771e5412328f90140a60c383f71bac0ec919b1d7dbc3eb72dd56e7aa99583615564f9f99b8ae4e837b758773a5b2e4c51348854c8389f008e05029db7f464a5ff2e01d5e6e626174affd30a00'
test_prev_tx = '01000000000101b9cb0da76784960e000d63f0453221aeeb6df97f2119d35c3051065bc9881eab0000000000fdffffff020000000000000000186a16546170726f6f74204654572120406269746275673432a059010000000000225120339ce7e165e67d93adb3fef88a6d4beed33f01fa876f05a225242b82a631abc00247304402204bf50f2fea3a2fbf4db8f0de602d9f41665fe153840c1b6f17c0c0abefa42f0b0220631fe0968b166b00cb3027c8817f50ce8353e9d5de43c29348b75b6600f231fc012102b14f0e661960252f8f37486e7fe27431c9f94627a617da66ca9678e6a2218ce1ffd30a00'

tx_parsed = bitcoinlib.transactions.Transaction.parse(test_tx)
prev_tx_parsed = bitcoinlib.transactions.Transaction.parse(test_prev_tx)


# -------------------------------
# 1. STEP: Build message to sign:
# -------------------------------

#print(json.dumps(tx_parsed.as_dict(), indent=4))
#print(json.dumps(prev_tx_parsed.as_dict(), indent=4))

# NOTE: This might be done differently:
prevouts = []
for txin in tx_parsed.as_dict()["inputs"]:
    prevouts.append([])
    txin_id = bytearray.fromhex(txin["prev_txid"])
    txin_id.reverse() # little endian encoded tx hash needed
    prevouts[-1].append(bytes(txin_id))
    prevouts[-1].append(int.to_bytes(txin["output_n"],4,'little'))
    # FROM PREVIOUS TX:
    # NOTE: Here, a method could be used, to get the data of this specific output from the blockchain:
    scriptPubKey = bytearray.fromhex(prev_tx_parsed.as_dict()["outputs"][txin["output_n"]]["script"])
    #scriptPubKey = bytearray.fromhex("5120339ce7e165e67d93adb3fef88a6d4beed33f01fa876f05a225242b82a631abc0")     # TODO Check if this script is correct!
    lengthScriptPubKey = len(scriptPubKey)
    prevouts[-1].append(int.to_bytes(lengthScriptPubKey,1,'little'))
    prevouts[-1].append(bytes(scriptPubKey))
    prevouts[-1].append(int.to_bytes(txin["sequence"],4,'little'))

test_sha_prevouts, test_sha_scriptpubkeys, test_sha_sequences, preimage_prevouts, preimage_scriptpubkeys, preimage_sequences = sha_txins(prevouts)

# From PREVIOUS TX from blockchain explorer
# --
prevouts_amounts = [
    int.to_bytes(88480 ,8,'little')
]
test_sha_amounts, preimage = sha_amounts(prevouts_amounts)
# --

outputs = []
for txout in tx_parsed.as_dict()["outputs"]:
    outputs.append([])
    outputs[-1].append(int.to_bytes(txout["value"],8,'little'))
    scriptPubKey = bytearray.fromhex(txout["script"])     
    lengthScriptPubKey = len(scriptPubKey)
    outputs[-1].append(int.to_bytes(lengthScriptPubKey,1,'little'))
    outputs[-1].append(bytes(scriptPubKey))
test_sha_outputs, test_sha_outputs_preimage = sha_outputs(outputs)

signature_message, preimage = create_signature_message_for_taproot_tx(
    hash_type=int.to_bytes(0,1,'little'), # If signature 64 byte, this is 0x00, otherwise it is given in signature byte 65
    nVersion=int.to_bytes(tx_parsed.as_dict()["version"],4,'little'),
    nLockTime=int.to_bytes(tx_parsed.as_dict()["locktime"],4,'little'),
    sha_prevouts=test_sha_prevouts,
    sha_amounts=test_sha_amounts,
    sha_scriptpubkeys=test_sha_scriptpubkeys,
    sha_sequences=test_sha_sequences,
    sha_outputs=test_sha_outputs,
    spend_type=int.to_bytes(0,1,'little'), # TODO Unclear if this is the correct flag
    outpoint=None,
    amount=None,
    scriptPubKey=None,
    nSequence=None,
    input_index=int.to_bytes(0,4,'little'), 
    have_annex=False, # TODO Unclear
    sha_annex=None,
    sha_single_output=None # TODO Unclear
)

# Check if the provided signature of the spender is correct:
test_witness_data = tx_parsed.as_dict()["inputs"][0]["witness"]
verified = schnorr_verify(signature_message,bytes(bytearray.fromhex(test_pubkey)),bytes(bytearray.fromhex(test_witness_data)))
print(">> verified: ",verified)


# -----------------------------
# 2. STEP: Build serizalied TX:
# -----------------------------

build_txins = []
for txin in tx_parsed.as_dict()["inputs"]:
    build_txins.append([])
    txin_id = bytearray.fromhex(txin["prev_txid"])
    txin_id.reverse() # little endian encoded tx hash needed
    build_txins[-1].append(bytes(txin_id))
    build_txins[-1].append(int.to_bytes(txin["output_n"],4,'little'))
    scriptSig = bytearray.fromhex(txin["script"])
    lengthScriptSig = len(scriptSig)
    build_txins[-1].append(int.to_bytes(lengthScriptSig,1,'little'))
    build_txins[-1].append(bytes(scriptSig))
    build_txins[-1].append(int.to_bytes(txin["sequence"],4,'little'))
build_count_txins = int.to_bytes(len(build_txins),1,'little')

build_txouts = []
for txout in tx_parsed.as_dict()["outputs"]:
    build_txouts.append([])
    build_txouts[-1].append(int.to_bytes(txout["value"],8,'little'))
    scriptPubKey = bytearray.fromhex(txout["script"])
    lengthScriptPubKey = len(scriptPubKey)
    build_txouts[-1].append(int.to_bytes(lengthScriptPubKey,1,'little'))
    build_txouts[-1].append(bytes(scriptPubKey))
build_count_txouts = int.to_bytes(len(build_txouts),1,'little')

# USE THE CORRESPONDING PRIVATE KEY FOR PUBLIC KEY
# The private key and aux rand for this example is NOT known. Hence, a random private key and aux rand value is used here:
TEST_PRIVATE_KEY = bytes_from_int(0xC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B14E5C9)
TEST_AUX_RAND = bytes_from_int(0xC87AA53824B4D7AE2EB035A2B5BBBCCC080E76CDC6D1692C4B0B62D798E6D906)
test_some_data = int.to_bytes(123456789, 8, 'little')
# Signing one TX input:
build_witness = [schnorr_sign_with_data(signature_message, TEST_PRIVATE_KEY, TEST_AUX_RAND, test_some_data)]
build_witness_data = [[int.to_bytes(len(build_witness),1,'little'), build_witness]]

serialized_signed_transaction, txid, txid_preimage = build_serialized_signed_transaction( 
    count_txin = build_count_txins,
    txins = build_txins,
    count_txout = build_count_txouts,
    txouts = build_txouts,
    witness_data = build_witness_data
    )

print(serialized_signed_transaction)





tx_structure = {
    "nVersion"                      :  {"size":  4, "type": "int", "value": None, "bytes": None, "byteorder": "little"},
    "marker"                        :  {"size":  1, "type": "int", "value": None, "bytes": None, "byteorder": "big"},
    "flag"                          :  {"size":  1, "type": "int", "value": None, "bytes": None, "byteorder": "big"},
    "count_txin"                    :  {"size":  1, "type": "int", "value": None, "bytes": None, "byteorder": "big"},
    "txin"                          :  {"size": "count_txin", "type": "list", "list": [], "elements":
        {   # Size of txin is elements of list
            "txin_hash"                 :  {"size": 32, "type": "hex", "value": None, "bytes": None, "byteorder": "little"},
            "txin_output"               :  {"size":  4, "type": "int", "value": None, "bytes": None, "byteorder": "little"},
            "txin_lengthScriptSig"      :  {"size":  1, "type": "int", "value": None, "bytes": None, "byteorder": "big"},
            "txin_scriptSig"            :  {"size": "txin_lengthScriptSig", "type" : "script", "value": None},
            "txin_nSequence"            :  {"size":  4, "type": "int", "value": None, "bytes": None, "byteorder": "little"}
        }
    },
    "count_txout"                   :  {"size":  1, "type": "int", "value": None, "bytes": None, "byteorder": "big"},
    "txout"                         :  {"size": "count_txout", "type": "list", "list": [], "elements":
        {   # Size of txout is elements of list
            "txout_value"               :  {"size":  8, "type": "int", "value": None, "bytes": None, "byteorder": "little"},
            "txout_lengthScriptPubKey"  :  {"size":  1, "type": "int", "value": None, "bytes": None, "byteorder": "big"},
            "txout_scriptPubKey"        :  {"size" : "txout_lengthScriptPubKey", "type" : "script", "value": None}
        }
    },
    "witness"                       :  {"size": "count_txin", "type": "list", "list": [], "elements":
        {   # Number of witness scripts depends on number of TX inputs
            "count_witnessElements"     :  {"size":  1, "type": "int", "value": None, "bytes": None, "byteorder": "big"},
            "witnessElements"           :  {"size": "count_witnessElements", "type": "list", "list": [], "elements":
                {   # Number of witness elements
                    "witness_lengthElement" :  {"size":  1, "type": "int", "value": None, "bytes": None, "byteorder": "big"},                           # Length of bytes
                    "witness_element"       :  {"size": "witness_lengthElement", "type" : "script", "value": None, "bytes": None}
                }
            }
        }
    },
    "nLockTime"                     :  {"size":  4, "type": "int", "value": None, "byteorder": "little", "bytes": None}
}