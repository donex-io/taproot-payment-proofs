import hashlib
from reference_implementations.schnorr_signatures.reference import *


def build_serialized_signed_transaction(
    nVersion: bytes,
    marker: bytes,
    flag: bytes,
    count_txin: bytes,
    txins: list,
    count_txout: bytes,
    txouts: list,
    witness_data: list,
    nLockTime: bytes
):

    serialized_signed_transaction = ""

    if len(nVersion) != 4:
        raise ValueError('nVersion must be a 4-byte array.')
    serialized_signed_transaction += nVersion.hex()
    nVersion_INT = int.from_bytes(nVersion, byteorder="little")

    # TODO is marker included in TXID?
    if len(marker) != 1:
        raise ValueError('marker must be a 1-byte array.')
    serialized_signed_transaction += marker.hex()

    # TODO is flag included in TXID?
    if len(flag) != 1:
        raise ValueError('flag must be a 1-byte array.')
    serialized_signed_transaction += flag.hex()

    if len(count_txin) != 1:
        raise ValueError('count_txin must be a 1-byte array.')
    serialized_signed_transaction += count_txin.hex()
    count_txin_INT = int.from_bytes(count_txin, byteorder="little")

    if len(txins) != count_txin_INT:
        raise ValueError('txins length must equal count_txin.')
    for txin in txins:
        if len(txin) != 5:
            raise ValueError('txin must contain 5 elements.')

        hash = txin[0]
        if len(hash) != 32:
            raise ValueError('hash must be a 32-byte array.')
        serialized_signed_transaction += hash.hex()

        output = txin[1]
        if len(output) != 4:
            raise ValueError('output must be a 4-byte array.')
        serialized_signed_transaction += output.hex()

        lengthScriptSig = txin[2]
        if len(lengthScriptSig) != 1:
            raise ValueError('lengthScriptSig must be a 1-byte array.')
        serialized_signed_transaction += lengthScriptSig.hex()
        lengthScriptSig_INT = int.from_bytes(lengthScriptSig, byteorder="little")

        if lengthScriptSig_INT > 0:
            scriptSig = txin[3]
            if len(scriptSig) != lengthScriptSig_INT:
                raise ValueError('scriptSig length must equal lengthScriptSig.')
            serialized_signed_transaction += scriptSig.hex()

        nSequence = txin[4]
        if len(nSequence) != 4:
            raise ValueError('nSequence must be a 4-byte array.')
        serialized_signed_transaction += nSequence.hex()

    if len(count_txout) != 1:
        raise ValueError('count_txout must be a 1-byte array.')
    serialized_signed_transaction += count_txout.hex()
    count_txout_INT = int.from_bytes(count_txout, byteorder="little")

    if len(txouts) != count_txout_INT:
        raise ValueError('txouts length must equal count_txout.')
    for txout in txouts:
        if len(txout) != 3:
            raise ValueError('txout must contain 3 elements.')

        value = txout[0]
        if len(value) != 8:
            raise ValueError('value must be a 8-byte array.')
        serialized_signed_transaction += value.hex()

        lengthScriptPubKey = txout[1]
        if len(lengthScriptPubKey) != 1:
            raise ValueError('lengthScriptPubKey must be a 1-byte array.')
        serialized_signed_transaction += lengthScriptPubKey.hex()
        lengthScriptPubKey_INT = int.from_bytes(lengthScriptPubKey, byteorder="little")

        if lengthScriptPubKey_INT > 0:
            scriptPubKey = txout[2]
            if len(scriptPubKey) != lengthScriptPubKey_INT:
                raise ValueError('scriptPubKey length must equal lengthScriptPubKey.')
            serialized_signed_transaction += scriptPubKey.hex()

    # Witness data not included in TXID
    txid_preimage = serialized_signed_transaction
    
    if nVersion_INT >= 1:   # TODO If tx version == 1, witness data is present. Is that statement true?
        if len(witness_data) != count_txin_INT:
            raise ValueError('witness_data length must equal count_txin.')
        for witness in witness_data:

            count_witness_elements = witness[0]
            if count_witness_elements == None:
                serialized_signed_transaction += "00"
            else:

                if len(count_witness_elements) != 1:
                    raise ValueError('count_witness_elements must be a 1-byte array.')
                serialized_signed_transaction += count_witness_elements.hex()
                count_witness_elements_INT = int.from_bytes(count_witness_elements, byteorder="little")

                if len(witness)-1 != count_witness_elements_INT:
                    raise ValueError('witness_elements length must equal count_witness_elements.')
                for i in range(1,count_witness_elements_INT):
                    witness_element = witness[i]
                    if len(witness_element) != 2:
                        raise ValueError('witness_element must contain 2 elements.')

                    lengthWitnessElement = witness_element[0]
                    if len(lengthWitnessElement) != 1:
                        raise ValueError('lengthWitnessElement must be a 1-byte array.')
                    serialized_signed_transaction += lengthWitnessElement.hex()
                    lengthWitnessElement_INT = int.from_bytes(lengthWitnessElement, byteorder="little")

                    witnessElement = witness_element[1]
                    if len(witnessElement) != lengthWitnessElement_INT:
                        raise ValueError('witnessElement length must equal lengthWitnessElement.')
                    serialized_signed_transaction += witnessElement.hex()

    if len(nLockTime) != 4:
        raise ValueError('nLockTime must be a 4-byte array.')
    serialized_signed_transaction += nLockTime.hex()

    txid_preimage += nLockTime.hex()

    def dSHA256 (input):
        return hashlib.sha256(hashlib.sha256(bytes(input)).digest()).digest()

    txid = dSHA256(bytes.fromhex(txid_preimage)[::-1]).hex()

    return serialized_signed_transaction, txid, txid_preimage

def tx_vsize(serialized_signed_transaction: bytes, txid_preimage: bytes):
    return len(txid_preimage) * 4  + (len(serialized_signed_transaction) - len(txid_preimage)) # TODO marker and flag


def sha_txins (txins: list):
    preimage_prevouts = bytearray.fromhex("")
    preimage_scriptpubkeys = bytearray.fromhex("")
    preimage_sequences = bytearray.fromhex("")
    for txin in txins:

        # Has to be little endian of tx hash
        hash = txin[0]
        if len(hash) != 32:
            raise ValueError('hash must be a 32-byte array.')
        preimage_prevouts.extend(hash)

        output = txin[1]
        if len(output) != 4:
            raise ValueError('output must be a 4-byte array.')
        preimage_prevouts.extend(output)

        lengthScriptSig = txin[2]
        if len(lengthScriptSig) != 1:
            raise ValueError('lengthScriptSig must be a 1-byte array.')
        lengthScriptSig_INT = int.from_bytes(lengthScriptSig, byteorder="little")
        preimage_scriptpubkeys.extend(lengthScriptSig)
        # TODO: Preimage of length of script required?

        if lengthScriptSig_INT > 0:
            scriptSig = txin[3]
            if len(scriptSig) != lengthScriptSig_INT:
                raise ValueError('scriptSig length must equal lengthScriptSig.')
            preimage_scriptpubkeys.extend(scriptSig)

        nSequence = txin[4]
        if len(nSequence) != 4:
            raise ValueError('nSequence must be a 4-byte array.')
        preimage_sequences.extend(nSequence)

    sha_prevouts = hashlib.sha256(bytes(preimage_prevouts)).digest()
    sha_scriptpubkeys = hashlib.sha256(bytes(preimage_scriptpubkeys)).digest()
    sha_sequences = hashlib.sha256(bytes(preimage_sequences)).digest()
    
    return sha_prevouts, sha_scriptpubkeys, sha_sequences, preimage_prevouts, preimage_scriptpubkeys, preimage_sequences

def sha_amounts (amounts: list):
    preimage = bytearray.fromhex("")
    for amount in amounts:
        if len(amount) != 8:
            raise ValueError('amount must be a 8-byte array.')
        preimage.extend(amount)
    return hashlib.sha256(bytes(preimage)).digest(), preimage

def sha_outputs (txouts: list):
    preimage = bytearray.fromhex("")
    for txout in txouts:
        if len(txout) != 3:
            raise ValueError('txout must contain 3 elements.')

        value = txout[0]
        if len(value) != 8:
            raise ValueError('value must be a 8-byte array.')
        preimage.extend(value)

        lengthScriptPubKey = txout[1]
        if len(lengthScriptPubKey) != 1:
            raise ValueError('lengthScriptPubKey must be a 1-byte array.')
        preimage.extend(lengthScriptPubKey)
        lengthScriptPubKey_INT = int.from_bytes(lengthScriptPubKey, byteorder="little")

        if lengthScriptPubKey_INT > 0:
            scriptPubKey = txout[2]
            if len(scriptPubKey) != lengthScriptPubKey_INT:
                raise ValueError('scriptPubKey length must equal lengthScriptPubKey.')
            preimage.extend(scriptPubKey)

    return hashlib.sha256(bytes(preimage)).digest(), preimage

SIGHASH_DEFAULT = bytearray.fromhex('00')          # A new hashtype which results in signing over the whole transaction just as for SIGHASH_ALL.
SIGHASH_ALL = bytearray.fromhex('01')
SIGHASH_NONE = bytearray.fromhex('02')
SIGHASH_SINGLE = bytearray.fromhex('03')
SIGHASH_ANYONECANPAY = bytearray.fromhex('80')     # Once an input signed with SIGHASH_ALL|ANYONECANPAY is added to a transaction outputs cannot be changed or added without that signature being invalidated.
# Note:
# SIGHASH_ANYONECANPAY | SIGHASH_ALL = '81'
# SIGHASH_ANYONECANPAY | SIGHASH_NONE = '82'
# SIGHASH_ANYONECANPAY | SIGHASH_SINGLE = '83'

SIGHASH_INPUT_MASK = bytearray.fromhex('80')
SIGHASH_OUTPUT_MASK = 3

def create_signature_message (
    hash_type: bytes,
    nVersion: bytes,
    nLockTime: bytes,
    sha_prevouts: bytes,
    sha_amounts: bytes,
    sha_scriptpubkeys: bytes,
    sha_sequences: bytes,
    sha_outputs: bytes,
    spend_type: bytes,
    outpoint: bytes,
    amount: bytes,
    scriptPubKey: bytes,
    nSequence: bytes,
    input_index: bytes,
    have_annex: bool,
    sha_annex: bytes,
    sha_single_output: bytes
):

    input_type = int.to_bytes(int.from_bytes(bytes(hash_type), byteorder='little') & int.from_bytes(bytes(SIGHASH_INPUT_MASK), byteorder='little'),1,'little')
    output_type = SIGHASH_ALL if (hash_type == SIGHASH_DEFAULT) else int.to_bytes((int.from_bytes(bytes(hash_type), byteorder='little') & int.from_bytes(bytes(SIGHASH_OUTPUT_MASK), byteorder='little')),1,'little')

# // Epoch
# static constexpr uint8_t EPOCH = 0;
# ss << EPOCH;
# https://github.com/bitcoin/bitcoin/blob/master/src/script/interpreter.cpp#L1530

# Taproot key path spending signature validation
# To validate a signature sig with public key q:
# * If the sig is 64 bytes long, return Verify(q, hashTapSighash(0x00 || SigMsg(0x00, 0)), sig)[20], where Verify is defined in BIP340.
# * If the sig is 65 bytes long, return sig[64] ≠ 0x00[21] and Verify(q, hashTapSighash(0x00 || SigMsg(sig[64], 0)), sig[0:64]).
# * Otherwise, fail[22].
# https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki#taproot-key-path-spending-signature-validation
# https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki#cite_note-20

    preimage = bytearray.fromhex("00")

# TAPROOT SPEC: 
# The function SigMsg(hash_type, ext_flag) computes the common portion of the message being signed as a byte array. It is implicitly also a function of the spending transaction and the outputs it spends, but these are not listed to keep notation simple.
# The parameter hash_type is an 8-bit unsigned value. The SIGHASH encodings from the legacy script system are reused, including SIGHASH_ALL, SIGHASH_NONE, SIGHASH_SINGLE, and SIGHASH_ANYONECANPAY. We define a new hashtype SIGHASH_DEFAULT (value 0x00) which results in signing over the whole transaction just as for SIGHASH_ALL. The following restrictions apply, which cause validation failure if violated:
# Using any undefined hash_type (not 0x00, 0x01, 0x02, 0x03, 0x81, 0x82, or 0x83[13]).
# Using SIGHASH_SINGLE without a "corresponding output" (an output with the same index as the input being verified).
# The parameter ext_flag is an integer in range 0-127, and is used for indicating (in the message) that extensions are appended to the output of SigMsg()[14].
# If the parameters take acceptable values, the message is the concatenation of the following data, in order (with byte size of each item listed in parentheses). Numerical values in 2, 4, or 8-byte are encoded in little-endian.
# https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki#common-signature-message

# Control:
# hash_type (1).

    if len(hash_type) != 1:
        raise ValueError('hash_type must be a 1-byte array.')
    preimage.extend(hash_type)

# Transaction data:
# nVersion (4): the nVersion of the transaction.

    if len(nVersion) != 4:
        raise ValueError('nVersion must be a 4-byte array.')
    preimage.extend(nVersion)

# nLockTime (4): the nLockTime of the transaction.

    if len(nLockTime) != 4:
        raise ValueError('nLockTime must be a 4-byte array.')
    preimage.extend(nLockTime)

# If the hash_type & 0x80 does not equal SIGHASH_ANYONECANPAY:

    if input_type.hex() != SIGHASH_ANYONECANPAY.hex():

    # sha_prevouts (32): the SHA256 of the serialization of all input outpoints.

        if len(sha_prevouts) != 32:
            raise ValueError('sha_prevouts must be a 32-byte array.')
        preimage.extend(sha_prevouts)

    # sha_amounts (32): the SHA256 of the serialization of all spent output amounts.

        if len(sha_amounts) != 32:
            raise ValueError('sha_amounts must be a 32-byte array.')
        preimage.extend(sha_amounts)

    # sha_scriptpubkeys (32): the SHA256 of all spent outputs' scriptPubKeys, serialized as script inside CTxOut.

        if len(sha_scriptpubkeys) != 32:
            raise ValueError('sha_scriptpubkeys must be a 32-byte array.')
        preimage.extend(sha_scriptpubkeys)

    # sha_sequences (32): the SHA256 of the serialization of all input nSequence.

        if len(sha_sequences) != 32:
            raise ValueError('sha_sequences must be a 32-byte array.')
        preimage.extend(sha_sequences)

# If hash_type & 3 does not equal SIGHASH_NONE or SIGHASH_SINGLE:
#
# BITCOIN CORE
# https://github.com/bitcoin/bitcoin/blob/master/src/script/interpreter.cpp#L1548
#  if (output_type == SIGHASH_ALL) {
#     ss << cache.m_outputs_single_hash;
# }

    if output_type.hex() == SIGHASH_ALL.hex():

    # sha_outputs (32): the SHA256 of the serialization of all outputs in CTxOut format.

        if len(sha_outputs) != 32:
            raise ValueError('sha_outputs must be a 32-byte array.')
        preimage.extend(sha_outputs)

# Data about this input:
# spend_type (1): equal to (ext_flag * 2) + annex_present, where annex_present is 0 if no annex is present, or 1 otherwise (the original witness stack has two or more witness elements, and the first byte of the last element is 0x50)
#
# BITCOIN CORE
# // Data about the input/prevout being spent
# assert(execdata.m_annex_init);
# const bool have_annex = execdata.m_annex_present;
# const uint8_t spend_type = (ext_flag << 1) + (have_annex ? 1 : 0); // The low bit indicates whether an annex is present.
# ss << spend_type;

    if len(spend_type) != 1:
        raise ValueError('spend_type must be a 1-byte array.')
    preimage.extend(spend_type)

# If hash_type & 0x80 equals SIGHASH_ANYONECANPAY:

    if input_type.hex() == SIGHASH_ANYONECANPAY.hex():

    # outpoint (36): the COutPoint of this input (32-byte hash + 4-byte little-endian).

        if len(outpoint) != 36:
            raise ValueError('outpoint must be a 36-byte array.')
        preimage.extend(outpoint)

    # amount (8): value of the previous output spent by this input.

        if len(amount) != 8:
            raise ValueError('amount must be a 8-byte array.')
        preimage.extend(amount)

    # scriptPubKey (35): scriptPubKey of the previous output spent by this input, serialized as script inside CTxOut. Its size is always 35 bytes.

        if len(scriptPubKey) != 35:
            raise ValueError('scriptPubKey must be a 35-byte array.')
        preimage.extend(scriptPubKey)

    # nSequence (4): nSequence of this input.

        if len(nSequence) != 4:
            raise ValueError('nSequence must be a 4-byte array.')
        preimage.extend(nSequence)

# If hash_type & 0x80 does not equal SIGHASH_ANYONECANPAY:

    else:

    # input_index (4): index of this input in the transaction input vector. Index of the first input is 0.

        if len(input_index) != 4:
            raise ValueError('input_index must be a 4-byte array.')
        preimage.extend(input_index)

# If an annex is present (the lowest bit of spend_type is set):

    if have_annex:

    # sha_annex (32): the SHA256 of (compact_size(size of annex) || annex), where annex includes the mandatory 0x50 prefix.

        if len(sha_annex) != 32:
            raise ValueError('sha_annex must be a 32-byte array.')
        preimage.extend(sha_annex)

# Data about this output:
# If hash_type & 3 equals SIGHASH_SINGLE:

    if output_type.hex() == SIGHASH_SINGLE.hex():

# sha_single_output (32): the SHA256 of the corresponding output in CTxOut format.

        if len(sha_single_output) != 32:
            raise ValueError('sha_single_output must be a 32-byte array.')
        preimage.extend(sha_single_output)

# BITCOIN CORE
# // Additional data for BIP 342 signatures
# if (sigversion == SigVersion::TAPSCRIPT) {
#     assert(execdata.m_tapleaf_hash_init);
#     ss << execdata.m_tapleaf_hash;
#     ss << key_version;
#     assert(execdata.m_codeseparator_pos_init);
#     ss << execdata.m_codeseparator_pos;
# }

# Hashes that go into the signature message and the message itself are now computed with a single SHA256 invocation instead of double SHA256. There is no expected security improvement by doubling SHA256 because this only protects against length-extension attacks against SHA256 which are not a concern for signature messages because there is no secret data. Therefore doubling SHA256 is a waste of resources. The message computation now follows a logical order with transaction level data first, then input data and output data. This allows to efficiently cache the transaction part of the message across different inputs using the SHA256 midstate. Additionally, sub-hashes can be skipped when calculating the message (for example `sha_prevouts` if SIGHASH_ANYONECANPAY is set) instead of setting them to zero and then hashing them as in BIP143. Despite that, collisions are made impossible by committing to the length of the data (implicit in hash_type and spend_type) before the variable length data.
# https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki#cite_note-16

    signature_message = tagged_hash("TapSighash", preimage) 

    return signature_message, preimage

