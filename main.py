# -------------------------------
# Imports
# -------------------------------

import sys
import os

import csv
import json
import string
import pickle

import bitcoinlib

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.append(os.path.dirname(SCRIPT_DIR))

# from features.reference_implementations.schnorr_signatures.reference import *
# from features.reference_implementations.bech32m_addresses.segwit_addr import *
from features.create_keys_and_addresses import *
from features.handle_invoices import *
from features.scan_utxo_set import *
from features.schnorr_signature_with_data import *
from features.tx_builder import *


# -------------------------------
# Bitcoin core RPC connection
# -------------------------------

# load bitcoin-rpc library, https://github.com/jgarzik/python-bitcoinrpc (sudo pip install python-bitcoinrpc)
from bitcoinrpc.authproxy import AuthServiceProxy, JSONRPCException

# setup JSON-rpc connection with bitcoind, credentials are set in bitcoin.conf
bt_cli = AuthServiceProxy("http://%s:%s@127.0.0.1:18332"%('admin', 'admin'), timeout=120)


# -------------------------------
# Functions
# -------------------------------

def locate_and_read_invoice(invoice_number):
    script_dir = os.path.dirname(__file__)
    rel_path = f'features/handle_invoices/invoice{invoice_number}.json'
    abs_file_path = os.path.join(script_dir, rel_path)
    json_file = open(abs_file_path, "r")
    invoice_dict = json.load(json_file)
    return invoice_dict

def read_keys_and_addresses(row_to_read):    
    script_dir = os.path.dirname(__file__)
    rel_path = "features/create_keys_and_addresses/keys_and_addresses.csv"
    abs_file_path = os.path.join(script_dir, rel_path)
    print(abs_file_path)
    with open(abs_file_path) as csvfile:
        csv_reader = csv.reader(csvfile, delimiter=' ')
        rows = [r for r in csv_reader]
        row = rows[row_to_read]
        address = row[0]
        private_key = row[1]
        public_key = row[2]
        return address, private_key, public_key


# -------------------------------
# Main script
# -------------------------------

invoice_data = locate_and_read_invoice(5511)
sending_address, sending_private_key, sending_public_key = read_keys_and_addresses(10)
recipient_address, recipient_private_key, recipient_public_key = read_keys_and_addresses(11)

# old function: pay_invoice(5511, recipient_public_key, sending_address, recipient_public_key, sending_public_key)

# read from invoice
invoice_dict = locate_and_read_invoice(5511) # read invoice number 5511
amount_to_send = invoice_dict['amount']

# if signature in invoice is valid, proceed with payment
if verify_invoice_signature(invoice_dict, bytearray.fromhex(recipient_public_key)):
    print('Invoice signature matches the provided public key. Continue to pay invoice...')
    
else: 
    raise ValueError('Invoice signature does not match the provided public key. Cannot pay invoice.')

# scan the utxo set of the sending address and return matching entry array
#utxo_scan_result = start_scanutxos(bt_cli, sending_address)
#f = open('store.pckl', 'wb')
#pickle.dump(utxo_scan_result, f)
#f.close()
f = open('store.pckl', 'rb')
utxo_scan_result = pickle.load(f)
f.close()

[utxo_counter, utxo_sum] = choose_matching_UTXOs(amount_to_send, 0, utxo_scan_result)
matching_utxo_array = return_matching_UTXOs(utxo_counter, utxo_scan_result)

# prepare inputs (aka previous outputs) for hashing 
prevouts_amounts = []
prevouts = []
for prevoutput in matching_utxo_array:
    prevouts_amounts.append(int.to_bytes(int(float(prevoutput['amount']) * 100000000), 8, 'little'))
    prevouts.append(output_input_bytes_list(
        bytearray.fromhex(prevoutput["txid"]), 
        prevoutput["vout"],
        bytearray.fromhex(prevoutput['scriptPubKey']),
        prevoutput['height']
    ))

txins = []
for txin in matching_utxo_array:
    txins.append(output_input_bytes_list(
        bytearray.fromhex(txin["txid"]), 
        txin["vout"],
        bytearray.fromhex(""),
        txin['height']
    ))

# hashing of input data
test_sha_prevouts, test_sha_scriptpubkeys, test_sha_sequences, preimage_prevouts, preimage_scriptpubkeys, preimage_sequences = sha_prevoutputs(prevouts)
test_sha_amounts, preimage = sha_amounts(prevouts_amounts)

# prepare spending and change output for hashing 
outputs = []

# 1st output: amount to send
outputs.append(txout_byte_list (amount_to_send,bytearray.fromhex('5120' + recipient_public_key)))

# # 2nd output: change to send back
outputs.append(txout_byte_list (utxo_sum - amount_to_send,bytearray.fromhex('5120' + recipient_public_key)))

# hashing of output data
test_sha_outputs, test_sha_outputs_preimage = sha_outputs(outputs)

signature_message, preimage = create_signature_message_for_taproot_tx(
    sha_prevoutpoints=test_sha_prevouts,
    sha_amounts=test_sha_amounts,
    sha_scriptpubkeys=test_sha_scriptpubkeys,
    sha_sequences=test_sha_sequences,
    sha_outputs=test_sha_outputs,
    input_index=int.to_bytes(0,4,'little')
)

data = json.dumps(invoice_dict).encode('utf-8')
private_key = bytes(bytearray.fromhex(sending_private_key))
witness = schnorr_sign_with_data(signature_message, private_key, int.to_bytes(0,32,'little'), data)
witness_data = [[int.to_bytes(1,1,'little'),[int.to_bytes(len(witness),1,'little'), witness]]]

serialized_signed_transaction, txid, txid_preimage = build_serialized_signed_transaction( 
    count_txin = int.to_bytes(len(txins),1,'little'),
    txins = txins,
    count_txout = int.to_bytes(len(outputs),1,'little'),
    txouts = outputs,
    witness_data = witness_data   
    )

print("serialized_signed_transaction",serialized_signed_transaction)

# Final step: broadcast TX to blockchain
# bt_cli.sendrawtransaction(signed_raw_hex_TX)