# ----------------------------------------
## Imports
# ----------------------------------------

import sys
import os

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.append(os.path.dirname(SCRIPT_DIR))

from features.reference_implementations.schnorr_signatures.reference import *

# NOTE
    # Calculate a deterministic 'j' which is acts as an one-time signing key per message.
    # Using the reference implementation of 'k' for this purpose:
def determine_j(msg: bytes, d: int, aux_rand: bytes) -> int:
    if not (1 <= d <= n - 1):
        raise ValueError('The secret key must be an integer in the range 1..n-1.')
    if len(msg) != 32:
        raise ValueError('The message must be a 32-byte array.')
    if len(aux_rand) != 32:
        raise ValueError('aux_rand must be 32 bytes instead of %i.' % len(aux_rand))
    t = xor_bytes(bytes_from_int(d), tagged_hash("BIP0340/aux", aux_rand))
    P = point_mul(G, d)
    j0 = int_from_bytes(tagged_hash("BIP0340/nonce", t + bytes_from_point(P) + msg)) % n
    if j0 == 0:
        raise RuntimeError('Failure. This happens only with negligible probability.')
    # NOTE
        # There is no restriction to 'J = j.G' with respect to even/odd.
        # However, to follow the command standard this is enforced here.
    j = n - j0 if not has_even_y(point_mul(G, j0)) else j0  
    return j

def modify_R(dat: int, J: Optional[Point]) -> Optional[Point]:
    D = point_mul(G, dat)
    assert D is not None
    return point_add(J, D)

def data_hash(J: Optional[Point], data: bytes) -> bytes:
    return tagged_hash("Data", data + bytes_from_point(J))

def modified_k(j: int, data: bytes) -> bytes:
    if not (1 <= j <= n - 1):
        raise ValueError('The nonce must be an integer in the range 1..n-1.')
    J = point_mul(G, j)
    h = data_hash(J,data)
    k0_mod = (j + int_from_bytes(h)) % n
    if k0_mod == 0:
        raise RuntimeError('Failure. This happens only with negligible probability.')
    R_mod = point_mul(G, k0_mod)
    assert R_mod is not None
    return n - k0_mod if not has_even_y(R_mod) else k0_mod

def schnorr_sign_with_data(msg: bytes, seckey: bytes, aux_rand: bytes, data: bytes) -> bytes:
    if len(msg) != 32:
        raise ValueError('The message must be a 32-byte array.')
    if len(aux_rand) != 32:
        raise ValueError('aux_rand must be 32 bytes instead of %i.' % len(aux_rand))
    d0 = int_from_bytes(seckey)
    if not (1 <= d0 <= n - 1):
        raise ValueError('The secret key must be an integer in the range 1..n-1.')
    P = point_mul(G, d0)
    assert P is not None
    d = d0 if has_even_y(P) else n - d0
    j = determine_j(msg, d, aux_rand)
    J = point_mul(G, j)
    assert J is not None
    k_mod = modified_k(j, data)
    R_mod = point_mul(G, k_mod)
    e = int_from_bytes(tagged_hash("BIP0340/challenge", bytes_from_point(R_mod) + bytes_from_point(P) + msg)) % n
    sig_mod = bytes_from_point(R_mod) + bytes_from_int((k_mod + e * d) % n)
    debug_print_vars()
    if not schnorr_verify(msg, bytes_from_point(P), sig_mod):
        raise RuntimeError('The created signature does not pass verification.')
    return sig_mod

# A (hashed) message 'e' is signed 
# with secret key 'd'
# using hash of some 'data' 
# and a random number 'j'
# such that signature 's':
#
#                        s   =     k                + (e*d)
#  Signer           <=>  s   = j   + h(data,Jx)     + (e*d)
#                 [  =>  s.G = j.G + h(data,Jx).G   + (e*d).G ]
#                 [ <=>  s.G =  J  + h(data,Jx).G   +  e.P    ]
#                 [ <=>  s.G =     R                +  e.P    ]
#  Sig verifier      =>  s.G ==    R                +  h(tag,Rx,Px,msg).P
#
#  Data verifier     =>    R == J  + h(data,Jx).G
#
# '(R,s)' is provided (on-chain) 
# to verify that message 'e' was signed
# by a 'd' that corresponds to 'P'.

def proof_data(sig: bytes, data: bytes, J: Optional[Point]) -> bool:
    if len(sig) != 64:
        raise ValueError('The signature must be a 64-byte array.')
    h = int_from_bytes(data_hash(J, data))
    R_proof = point_add(J,point_mul(G, h))
    x_R_proof = bytes_from_point(R_proof)
    x_R_sig = sig[0:32]
    return x_R_proof == x_R_sig