# ----------------------------------------
## Handle invoices
# ----------------------------------------

# function to create unsigned invoice
def create_unsigned_invoice(invoice_number, recipient_address, amount):   
    unsigned_invoice_data = {
        "invoice_number" : invoice_number,            
        "recipient_address" : recipient_address, # P2TR address
        "amount" : amount, # amount in Satoshis
    }
    return unsigned_invoice_data

from reference_implementations.schnorr_signatures.reference import *
import hashlib

def create_invoice_signature(unsigned_invoice, priv_key):
    unsigned_invoice_bytes = json.dumps(unsigned_invoice).encode('utf-8')
    msg = hashlib.sha256(unsigned_invoice_bytes).digest()
    signature = schnorr_sign(msg, bytearray.fromhex(priv_key), int.to_bytes(1, 32, 'little')) # third argument = 1 --> deterministic k / no randomness applied for this signature
    return signature

def verify_invoice_signature(signed_invoice, public_key):
    invoice = signed_invoice
    sig = invoice["signature"]
    sig = bytearray.fromhex(sig)
    invoice.pop("signature")
    msg = hashlib.sha256(json.dumps(invoice).encode('utf-8')).digest()
    return schnorr_verify(msg, public_key, sig) # schnorr_verify(msg: bytes, pubkey: bytes, sig: bytes) -> bool

import json

def append_invoice_signature(unsigned_invoice_input, signature):
    invoice = unsigned_invoice_input
    invoice["signature"] = signature.hex()
    return invoice

def write_invoice_to_file(signed_invoice):   
    
    # Determine file path
    import os
    script_dir = os.path.dirname(__file__)
    invoice_number = signed_invoice["invoice_number"]
    rel_path = f'handle_invoices/invoice{invoice_number}.json'
    abs_file_path = os.path.join(script_dir, rel_path)
    
    # Determine file path
    with open(abs_file_path, 'w', encoding='utf-8') as f:
        json.dump(signed_invoice, f, ensure_ascii=False, indent=4)
    print('Writing invoice to json file was successful.')