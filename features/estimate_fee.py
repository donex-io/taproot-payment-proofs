# ----------------------------------------
## Estimate fee 
# ----------------------------------------

# estimate fee rate in satoshi/vB
def estimate_fee_per_vSize(bt_cli_object, number_of_blocks_to_confirm):
        estimatesmartfee_return_object = bt_cli_object.estimatesmartfee(number_of_blocks_to_confirm)
        estimated_fee_per_vSize = int(estimatesmartfee_return_object['feerate']*100000)
        return estimated_fee_per_vSize

# calculate tx fee in satoshi
def calculate_tx_fee(tx_vSize, estimated_fee_per_vSize):
        tx_fee = tx_vSize * estimated_fee_per_vSize
        return tx_fee