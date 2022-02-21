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
serialized_signed_transaction, txid = build_serialized_signed_transaction(
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
print('serialized_signed_transaction >> ', serialized_signed_transaction)
print('txid >> ', txid)


example_sha_prevouts, example_sha_scriptpubkeys, example_sha_sequences = sha_txins(example_txin)
example_sha_amounts = sha_amounts(example_txin_amounts)
example_sha_outputs = sha_outputs(example_txouts)
example_input_to_sign = int.to_bytes(0,4,'little')

signature_message = create_signature_message(
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

print('sighash >> ', signature_message.hex())