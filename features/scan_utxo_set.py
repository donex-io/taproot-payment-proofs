# ----------------------------------------
## Scan UTXO set
# ----------------------------------------

def start_scanutxos(bt_cli_object, addr):
        scan_objects = [f"addr({addr})"]
        scan_result = bt_cli_object.scantxoutset('start', scan_objects)
        return scan_result

def query_status_scanutxos(bt_cli_object):
        scan_status = bt_cli_object.scantxoutset('status')
        return scan_status