# ----------------------------------------
## Import functions
# ----------------------------------------

import sys
import os

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.append(os.path.dirname(SCRIPT_DIR))

from handle_invoices import *

# ----------------------------------------
## Conduct tests
# ----------------------------------------

import json
import random

# In this example, for the sake of simplicity, the invoice is signed with the private key belonging to target address 

target_address = 'tb1pkyyw2h46qw7g9cjhut3xd28rlzjs2qtqn2ang72etwp89et27x8se4tp38'
private_key = '617cfaeec21347690025de578404bb6ae32c476be239bcd379ac16e670031d6b'
public_key = 'b108e55eba03bc82e257e2e266a8e3f8a50501609abb3479595b8272e56af18f'

unsigned_invoice = create_unsigned_invoice(random.randint(1111,9999), target_address, 25000)

# print(json.dumps(unsigned_invoice, indent=4))

signature = create_invoice_signature(unsigned_invoice, private_key)

signed_invoice = append_invoice_signature(unsigned_invoice, signature)

print(json.dumps(signed_invoice, indent=4))

write_invoice_to_file(signed_invoice)

print(f'Signature verification with respect to public key {public_key} yields: {verify_invoice_signature(signed_invoice, bytearray.fromhex(public_key))}')

