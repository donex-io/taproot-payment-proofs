import sys
import os

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.append(os.path.dirname(SCRIPT_DIR))

from tx_builder import *

# Example data

example_hash_type = SIGHASH_ALL

example_nVersion = int.to_bytes(1,4,'little')

example_nLockTime = int.to_bytes(0,4,'little')

example_flag = int.to_bytes(1,1,'little')

example_marker = int.to_bytes(0,1,'little')

example_txin = [
        [
            bytes([32] * 32),
            bytes([4] * 4),
            int.to_bytes(0,1,'little'),
            None,
            bytes([4] * 4)
        ],
        [
            bytes([32] * 32),
            bytes([4] * 4),
            int.to_bytes(0,1,'little'),
            None,
            bytes([4] * 4)
        ]
    ]
example_count_txins = int.to_bytes(len(example_txin),1,'little')

example_txin_amounts = [int.to_bytes(100000,8,'little'),int.to_bytes(200000,8,'little')]

example_txouts = [
        [
            bytes([8] * 8),
            int.to_bytes(12,1,'little'),
            bytes([11] * 12)
        ],
        [
            bytes([8] * 8),
            int.to_bytes(12,1,'little'),
            bytes([11] * 12)
        ]
    ]
example_count_txouts = int.to_bytes(len(example_txouts),1,'little')

example_witness_data = [
        [
            int.to_bytes(2,1,'little'),
            [
                int.to_bytes(14,1,'little'),
                bytes([13] * 14)
            ],
            [
                int.to_bytes(16,1,'little'),
                bytes([15] * 16)
            ]
        ],
        [
            int.to_bytes(2,1,'little'),
            [
                int.to_bytes(14,1,'little'),
                bytes([13] * 14)
            ],
            [
                int.to_bytes(16,1,'little'),
                bytes([15] * 16)
            ]
        ]
    ]


# Example serizalied tx
serialized_signed_transaction, txid, txid_preimage = build_serialized_signed_transaction(
    nVersion=example_nVersion,
    marker=example_marker,
    flag=example_flag,
    count_txin=example_count_txins,
    txins=example_txin,
    count_txout=example_count_txouts,
    txouts=example_txouts,
    witness_data=example_witness_data,
    nLockTime=example_nLockTime
)
#print('serialized_signed_transaction >> ', serialized_signed_transaction)
#print('txid >> ', txid)


example_sha_prevouts, example_sha_scriptpubkeys, example_sha_sequences, preimage_prevouts, preimage_scriptpubkeys, preimage_sequences = sha_txins(example_txin)
example_sha_amounts = sha_amounts(example_txin_amounts)
example_sha_outputs = sha_outputs(example_txouts)
example_input_to_sign = int.to_bytes(0,4,'little')

signature_message, preimage = create_signature_message(
    hash_type=example_hash_type,
    nVersion=example_nVersion,
    nLockTime=example_nLockTime,
    sha_prevouts=example_sha_prevouts,
    sha_amounts=example_sha_amounts,
    sha_scriptpubkeys=example_sha_scriptpubkeys,
    sha_sequences=example_sha_sequences,
    sha_outputs=example_sha_outputs,
    spend_type=example_flag, # TODO Unclear if factor of 2 has to be used
    outpoint=None,
    amount=None,
    scriptPubKey=None,
    nSequence=None,
    input_index=example_input_to_sign,
    have_annex=False,
    sha_annex=None,
    sha_single_output=None
)

#print('sighash >> ', signature_message.hex())






# -------- Real world example --------




# Example https://blockstream.info/tx/37777defed8717c581b4c0509329550e344bdc14ac38f71fc050096887e535c8?expand

test_witness_data = 'a60c383f71bac0ec919b1d7dbc3eb72dd56e7aa99583615564f9f99b8ae4e837b758773a5b2e4c51348854c8389f008e05029db7f464a5ff2e01d5e6e626174a'
test_pubkey = '339ce7e165e67d93adb3fef88a6d4beed33f01fa876f05a225242b82a631abc0'
test_tx = '01000000000101d1f1c1f8cdf6759167b90f52c9ad358a369f95284e841d7a2536cef31c0549580100000000fdffffff020000000000000000316a2f49206c696b65205363686e6f7272207369677320616e6420492063616e6e6f74206c69652e204062697462756734329e06010000000000225120a37c3903c8d0db6512e2b40b0dffa05e5a3ab73603ce8c9c4b7771e5412328f90140a60c383f71bac0ec919b1d7dbc3eb72dd56e7aa99583615564f9f99b8ae4e837b758773a5b2e4c51348854c8389f008e05029db7f464a5ff2e01d5e6e626174affd30a00'


sys.path.insert(1, '/Users/rob/Documents/GitHub/taproot-payment-proofs/features/tx_builder/bitcoinlib_package')
sys.path.insert(1, '/Users/rob/Library/CloudStorage/OneDrive-DonexUG(haftungsbeschränkt)/General/01 Projects/06 L2.auction/Python testing/Schnorr sigs/Libs/ecdsa-0.10')
import ecdsa
import bitcoinlib

tx_parsed = bitcoinlib.transactions.Transaction.parse(test_tx)
#print(tx_parsed.as_json())

prevouts = []
for txin in tx_parsed.as_dict()["inputs"]:
    prevouts.append([])
    txin_id = bytearray.fromhex(txin["prev_txid"])
    txin_id.reverse() # little endian encoded tx hash needed
    prevouts[-1].append(bytes(txin_id))
    prevouts[-1].append(int.to_bytes(txin["output_n"],4,'little'))
    # From PREVIOUS TX from blockchain explorer
    scriptSig = bytearray.fromhex("5120339ce7e165e67d93adb3fef88a6d4beed33f01fa876f05a225242b82a631abc0")     # TODO Check if this script is correct!
    lengthScriptSig = len(scriptSig)
    prevouts[-1].append(int.to_bytes(lengthScriptSig,1,'little'))
    prevouts[-1].append(bytes(scriptSig))
    prevouts[-1].append(int.to_bytes(txin["sequence"],4,'little'))


test_sha_prevouts, test_sha_scriptpubkeys, test_sha_sequences, preimage_prevouts, preimage_scriptpubkeys, preimage_sequences = sha_txins(prevouts)


# From PREVIOUS TX from blockchain explorer
# --
prevouts_amounts = [
    int.to_bytes(88480 ,8,'little')
]
test_sha_amounts = sha_amounts(prevouts_amounts)
# --

outputs = []
for txout in tx_parsed.as_dict()["outputs"]:
    outputs.append([])
    outputs[-1].append(int.to_bytes(txout["value"],8,'little'))
    scriptPubKey = bytearray.fromhex(txout["script"])     # TODO Check if this script is correct!
    lengthScriptPubKey = len(scriptPubKey)
    outputs[-1].append(int.to_bytes(lengthScriptPubKey,1,'little'))
    outputs[-1].append(bytes(scriptPubKey))
test_sha_outputs, test_sha_outputs_preimage = sha_outputs(outputs)
print(">> Outputs:", tx_parsed.as_dict()["outputs"])
print(">> test_sha_outputs_preimage:", test_sha_outputs_preimage.hex())
print(">> test_sha_outputs:",test_sha_outputs.hex())

signature_message, preimage = create_signature_message(
    hash_type=int.to_bytes(0,1,'little'), # TODO How to know?
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
    input_index=int.to_bytes(0,4,'little'), # TODO Unclear if this is anyone can spend or sighash all
    have_annex=False, # TODO Unclear
    sha_annex=None,
    sha_single_output=None # TODO Unclear
)
print(">> preimage: ", preimage.hex())
#print(">> signature_message: ", signature_message.hex())

sys.path.insert(1, '/Users/rob/Documents/GitHub/taproot-payment-proofs/features/reference_implementations/schnorr_signatures')
from reference import *

#print(">> test_pubkey: ",test_pubkey)
#print(">> test_witness_data: ",test_witness_data)
verified = schnorr_verify(signature_message,bytes(bytearray.fromhex(test_pubkey)),bytes(bytearray.fromhex(test_witness_data)))
print(">> verified: ",verified)

