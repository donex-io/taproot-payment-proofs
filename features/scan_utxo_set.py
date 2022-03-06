# ----------------------------------------
## Scan UTXO set
# ----------------------------------------

def start_scanutxos(bt_cli_object, addr):
        print(f'Start scanning UTXOs for address {addr} ... this might take a while ...', '\n')
        scan_objects = [f"addr({addr})"]
        scan_result = bt_cli_object.scantxoutset('start', scan_objects)
        return scan_result


def convert_utxo_value_to_satoshi(scanned_amount):
        return int(float(scanned_amount) * 100000000) # convert dict type decimal.Decimal denominated in BTC to integer denominated in Satoshi 


# choose_matching_UTXOs() looks at the current utxos and returns how many utxos are needed for a given amount to send, starting from utxo 0 and counting up 
# the total amount in Satoshis of those utxos is returned as well
 
def choose_matching_UTXOs(amount_to_send: int, fee: int, scan_res):       
        if convert_utxo_value_to_satoshi(scan_res['total_amount']) < (amount_to_send + fee):
                raise ValueError('Insufficient funds available in UTXOs.') # check whether utxos' total is sufficient
        utxo_counter = 0
        matching_utxo_sum = 0
        while matching_utxo_sum < (amount_to_send + fee):                
                matching_utxo_sum += convert_utxo_value_to_satoshi(scan_res['unspents'][utxo_counter]['amount'])
                utxo_counter += 1
        return [utxo_counter, matching_utxo_sum]


# return_matching_UTXOs() takes results from choose_matching_UTXOs() and returns these utxos in their dict format

def return_matching_UTXOs(utxo_count, scan_res):
        matching_UTXOs = []    
        for x in range(utxo_count):
                matching_UTXOs.append(scan_res['unspents'][x])
        return matching_UTXOs

import yaml

def pretty_print_utxo(scan_res):
        print(yaml.dump(scan_res, default_flow_style=False))   

# def query_status_scanutxos(bt_cli_object):
#         scan_status = bt_cli_object.scantxoutset('status')
#         return scan_status