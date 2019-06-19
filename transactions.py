#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Sun Mar 31 18:52:14 2019

@author: marina
"""
import sys
if sys.version_info.major < 3:
    sys.stderr.write('Sorry, Python 3.x required by this example.\n')
    sys.exit(1)

import hashlib
import bitcoin
import random
import string
import bitcoin.rpc
from collections import defaultdict
from bitcoin import signmessage
from  bitcoin.rpc import *
from bitcoin import core
from bitcoin import params
from bitcoin.core import *
from blockchain import pushtx
from bitcoin import SelectParams
from bitcoin.base58 import *
from bitcoin.core import b2x, lx, COIN, COutPoint, Hash160
from bitcoin.core.script import *
from bitcoin.core.scripteval import VerifyScript, SCRIPT_VERIFY_P2SH, OP_NOP3
from bitcoin.wallet import CBitcoinAddress, CBitcoinSecret

SelectParams('regtest')

# Aux method to generate a random string of fixed length
def randomString(stringLength=30):
    letters = string.ascii_lowercase
    return ''.join(random.choice(letters) for i in range(stringLength)).encode('utf-8')

# Aux method to generate keys for Commitment Transactions
def generateKeys():
    # Third Parties Key Pairs. There are two group of third parties (third_a and third_b). Each of them composed by 3 third parties.
    third_a_keypairs = []
    third_b_keypairs = []
    i = 0
    
    while (i < 3):
        h_a = hashlib.sha256(randomString()).digest()
        sk_a = CBitcoinSecret.from_secret_bytes(h_a)
        pk_a = sk_a.pub
        
        h_b = hashlib.sha256(randomString()).digest()
        sk_b = CBitcoinSecret.from_secret_bytes(h_b)
        pk_b = sk_b.pub       
        
        keyPair_a = [pk_a,sk_a]
        keyPair_b = [pk_b,sk_b]
        third_a_keypairs.append(keyPair_a)
        third_b_keypairs.append(keyPair_b)
        i+=1
        
    # Create Key Pairs for IoT device and IoT Gateway. There should be a new key pair for each new commitment transaction.
    # I am creating a set of 10 keypairs to perform 10 commitment transactions.
    # Each device is going to have 3 keypairs for each commitment transaction: 
    # pk_A,B_i_a,b,c and sk_A,B_i_a,b,c where A and B are the devices, and i is the number of the transaction
    devices_keypairs = defaultdict(dict)
    i = 0
    
    for i in range(10):
        keys_device = defaultdict(list)
        for j in range(2):
            
            h_a = hashlib.sha256(randomString()).digest()
            sk_a = CBitcoinSecret.from_secret_bytes(h_a)
            pk_a = sk_a.pub
            
            h_b = hashlib.sha256(randomString()).digest()
            sk_b = CBitcoinSecret.from_secret_bytes(h_b)
            pk_b = sk_b.pub
            
            h_c = hashlib.sha256(randomString()).digest()
            sk_c = CBitcoinSecret.from_secret_bytes(h_c)
            pk_c = sk_c.pub
            
            #Only required for A
            h_rc = hashlib.sha256(randomString()).digest()
            sk_rc = CBitcoinSecret.from_secret_bytes(h_rc)
            pk_rc = sk_rc.pub
            
            keys_device[j] = [[pk_a,sk_a],[pk_b,sk_b],[pk_c,sk_c],[pk_rc,sk_rc]]
            devices_keypairs[i][j] = keys_device[j]
            
    return third_a_keypairs, third_b_keypairs, devices_keypairs
    
def fundingTx(seckeyA1, seckeyB1, txin, value_in, txin_redeemScript, txin_scriptPubKey): 

    # Generate redeem script and locking script
    r_S = CScript([OP_2, seckeyA1.pub, seckeyB1.pub, OP_2, OP_CHECKMULTISIG])
    #r_S_Hash = Hash160(r_S)
    #l_S = CScript([OP_HASH160,r_S_Hash, OP_EQUAL])
    
    # Create Transaction
    txout = CMutableTxOut(value_in-0.001*COIN,r_S)
    tx = CMutableTransaction([txin], [txout])

    # Sign Transaction
    sighash = SignatureHash(txin_redeemScript, tx, 0, SIGHASH_ALL)
    sigA = seckeyA1.sign(sighash) + bytes([SIGHASH_ALL])
      
    # Create Unlocking Script
    txin.scriptSig = CScript([sigA, txin_redeemScript])
    
    # Verify Scripts
    VerifyScript(txin.scriptSig, txin_scriptPubKey, tx, 0, (SCRIPT_VERIFY_P2SH,))

    return r_S, tx

def closingTx(seckeyA1, seckeyB1, txin, seckeyA2, seckeyB2, value_in2, txin_redeemScript):
    
    # Create Locking Scripts
    l_SA = CScript([OP_DUP, OP_HASH160, Hash160(seckeyA2.pub), OP_EQUALVERIFY, OP_CHECKSIG])
    l_SB = CScript([OP_DUP, OP_HASH160, Hash160(seckeyB2.pub), OP_EQUALVERIFY, OP_CHECKSIG])
    
    # Create Transaction 
    txout1 = CMutableTxOut(value_in2 - 0.005*COIN, CScript([l_SA]))
    txout2 = CMutableTxOut(0.001*COIN, CScript([l_SB]))
    txout = [txout1, txout2]
    tx = CMutableTransaction([txin], txout)

    # Sign Transaction
    sighash = SignatureHash(txin_redeemScript, tx, 0, SIGHASH_ALL)
    sigA = seckeyA1.sign(sighash) + bytes([SIGHASH_ALL])
    sigB = seckeyB1.sign(sighash) + bytes([SIGHASH_ALL])

    # Create Unlocking Script    
    txin.scriptSig  = CScript([OP_0, sigA, sigB, txin_redeemScript])
    
    # Verify Scripts
    txin_scriptPubKey = txin_redeemScript.to_p2sh_scriptPubKey()
    VerifyScript(txin.scriptSig, txin_scriptPubKey, tx, 0, (SCRIPT_VERIFY_P2SH,))
    
    return  l_SA, l_SB, tx

def commitmentA(seckeyA1, seckeyB1, ft_id,tx_index, devices_keypairs, third_a_keypairs, value_in2, txin_redeemScript):
    
    txid = ft_id
    vout = 0
    txin = CMutableTxIn(COutPoint(txid, vout))
    
    # Devices keys
        #Indexes: [x][y][z]
        # x: 0= IoT (device A), 1 = Gateway (device B)
        # y: 0 = 'a' keypair, 1 = 'b' keypair, 2 = 'c' keypair
        # z: 0 = pubKey, 1 = secKey
    pk_A_a = devices_keypairs[tx_index][0][0][0]
    pk_B_b = devices_keypairs[tx_index][1][1][0]
    pk_A_c = devices_keypairs[tx_index][0][2][0]
    
    sk_A_a = devices_keypairs[tx_index][0][0][1]
    sk_B_b = devices_keypairs[tx_index][1][1][1]
    
    # Third parties public keys
        # Indexes: [x][y]
        # x = 0,1,2 each of the third parties
        # y = 0 public key, y = 1 secret key       
    pk_3_a_0 = third_a_keypairs[0][0]
    pk_3_a_1 = third_a_keypairs[1][0]
    
    sk_3_b_0 = third_a_keypairs[0][1]
    sk_3_b_1 = third_a_keypairs[1][1]

    # OP_NOP3 is the equivalent to OP_CHECKSEQUENCEVERIFY 
    # https://bitcoin.org/en/release/v0.13.0#low-level-rpc-changes
    # 100 = W, Number of blocks before the transaction can be published
    l_SA = CScript([OP_DUP, OP_HASH160,Hash160(pk_A_a), OP_EQUALVERIFY, OP_CHECKSIG])
    l_SA1 = CScript([100,OP_NOP3, OP_DROP, l_SA])
    l_SA2 = CScript([OP_DUP, OP_HASH160, Hash160(pk_B_b), OP_EQUALVERIFY, OP_CHECKSIG, OP_DROP])
    l_SA3 = CScript([OP_DUP, OP_HASH160, Hash160(pk_A_c), OP_EQUALVERIFY, OP_CHECKSIG])
    
    # Output 1
    l_SA = CScript([OP_IF, l_SA1, OP_ELSE, l_SA2, l_SA3, OP_ENDIF]) 
    
    # Output 2
    l_SB = CScript([OP_DUP, OP_HASH160, Hash160(pk_B_b), OP_EQUALVERIFY, OP_CHECKSIG])   
    
    # Output 3
    l_S3 = CScript([OP_1, pk_3_a_0, pk_3_a_1, OP_2, OP_CHECKMULTISIG])
    
    txout1 = CMutableTxOut(value_in2 - 0.005*COIN,CScript([l_SA]))
    txout2 = CMutableTxOut(0.001*COIN,CScript([l_SB]))
    txout3 = CMutableTxOut(0.001*COIN,CScript([l_S3]))
    txout = [txout1, txout2, txout3]
    tx = CMutableTransaction([txin], txout)

    # Sign Transaction
    sighash = SignatureHash(txin_redeemScript, tx, 0, SIGHASH_ALL)
    sigA = seckeyA1.sign(sighash) + bytes([SIGHASH_ALL])
    sigB = seckeyB1.sign(sighash) + bytes([SIGHASH_ALL])

    # Create Unlocking Script    
    txin.scriptSig  = CScript([OP_0, sigA, sigB, txin_redeemScript])
    
    # Verify Scripts
    txin_scriptPubKey = txin_redeemScript.to_p2sh_scriptPubKey()
    VerifyScript(txin.scriptSig, txin_scriptPubKey, tx, 0, (SCRIPT_VERIFY_P2SH,))   

    return l_SA, l_SB, l_S3, tx

def commitmentB(seckeyA1, seckeyB1, ft_id, tx_index, devices_keypairs, third_b_keypairs, value_in2, txin_redeemScript):
           
    txid = ft_id
    vout = 0 
    txin = CMutableTxIn(COutPoint(txid, vout))
    
    # Devices keys
        #Indexes: [x][y][z]
        # x: 0= IoT (device A), 1 = Gateway (device B)
        # y: 0 = 'a' keypair, 1 = 'b' keypair, 2 = 'c' keypair
        # z: 0 = pubKey, 1 = secKey
    pk_A_b = devices_keypairs[tx_index][0][1][0]
    sk_A_b = devices_keypairs[tx_index][0][1][1]
    
    pk_B_a = devices_keypairs[tx_index][1][0][0]
    sk_B_a = devices_keypairs[tx_index][1][0][1]
    
    pk_B_c = devices_keypairs[tx_index][1][2][0]
    sk_B_c = devices_keypairs[tx_index][1][2][1]
    
    # Third parties public keys
        # Indexes: [x][y]
        # x = 0,1,2 each of the third parties
        # y = 0 public key, y = 1 secret key
        
    pk_3_b_0 = third_b_keypairs[0][0]
    sk_3_b_0 = third_b_keypairs[0][1]
    
    pk_3_b_1 = third_b_keypairs[1][0] 
    sk_3_b_1 = third_b_keypairs[1][1]
    
    l_SB = CScript([OP_DUP, OP_HASH160,Hash160(pk_B_a), OP_EQUALVERIFY, OP_CHECKSIG])
    l_SB1 = CScript([100, OP_NOP3, OP_DROP, l_SB])
    l_SB2 = CScript([OP_1, pk_3_b_0, pk_3_b_1, OP_2, OP_CHECKMULTISIG, OP_DROP])
    l_SB3 = CScript([OP_DUP, OP_HASH160, Hash160(pk_B_c), OP_EQUALVERIFY, OP_CHECKSIG, OP_DROP])
    l_SB4 = CScript([OP_DUP, OP_HASH160, Hash160(pk_A_b), OP_EQUALVERIFY, OP_CHECKSIG])
    
    # Output 1
    l_SB = CScript([OP_IF, l_SB1, OP_ELSE, l_SB2, l_SB3, l_SB4, OP_ENDIF])  
    
    # Output 2
    l_SA = CScript([OP_DUP, OP_HASH160, Hash160(pk_A_b), OP_EQUALVERIFY, OP_CHECKSIG])
    
     
    txout1 = CMutableTxOut(value_in2 - 0.001*COIN,CScript([l_SA]))
    txout2 = CMutableTxOut(0.0001*COIN,CScript([l_SB]))
    txout = [txout1, txout2]
    tx = CMutableTransaction([txin], txout)
        
    # Sign Transaction
    sighash = SignatureHash(txin_redeemScript, tx, 0, SIGHASH_ALL)
    sigA = seckeyA1.sign(sighash) + bytes([SIGHASH_ALL])
    sigB = seckeyB1.sign(sighash) + bytes([SIGHASH_ALL])

    # Create Unlocking Script    
    txin.scriptSig  = CScript([OP_0, sigA, sigB, txin_redeemScript])
    
    # Verify Scripts
    txin_scriptPubKey = txin_redeemScript.to_p2sh_scriptPubKey()
    VerifyScript(txin.scriptSig, txin_scriptPubKey, tx, 0, (SCRIPT_VERIFY_P2SH,)) 

    secKeys = [sk_A_b, sk_B_c, sk_3_b_0]
    return l_SA, l_SB, tx, secKeys

def recoveryTx(secKeys, txin,tx_index, devices_keypairs,third_a_keypairs, third_b_keypairs, value_in, txin_l_S):
    
    
    # Devices keys and signatures
    pk_A_b = devices_keypairs[tx_index][0][1][0]
    sk_A_b = devices_keypairs[tx_index][0][1][1]
       
    pk_B_c = devices_keypairs[tx_index][1][2][0]
    sk_B_c = devices_keypairs[tx_index][1][2][1]
    
    pk_B_b = devices_keypairs[tx_index][1][1][0]
    sk_B_b = devices_keypairs[tx_index][1][1][1]
    
    pk_A_c = devices_keypairs[tx_index][0][2][0]
    
    pk_A_rc = devices_keypairs[tx_index][0][3][0]
    sk_A_rc = devices_keypairs[tx_index][0][3][1]
  
    # Third parties keys
    pk_3_a_0 = third_a_keypairs[0][0]
    sk_3_a_0 = third_a_keypairs[0][1]
    
    pk_3_a_1 = third_a_keypairs[1][0]
    sk_3_a_1 = third_a_keypairs[1][1]
    
    pk_3_b_alpha = third_b_keypairs[0][0]
    sk_3_b_alpha = third_b_keypairs[0][1]
    
    pk_3_b_omega = third_b_keypairs[1][0]
    sk_3_b_omega = third_b_keypairs[1][1]
        
    # Out 1
    l_S1 = CScript([OP_DUP, OP_HASH160, Hash160(pk_A_rc), OP_EQUALVERIFY, OP_CHECKSIG])     
        
    # Out 2
    l_S2 = CScript([OP_DUP, OP_HASH160, Hash160(pk_3_b_omega), OP_EQUALVERIFY, OP_CHECKSIG])

    # Out 3
    l_S3 = CScript([OP_1, pk_3_a_0, pk_3_a_1, OP_2, OP_CHECKMULTISIG, OP_DROP])     

    # Create tx
       
    txout1 = CMutableTxOut(value_in - 0.003*COIN,CScript([l_S1]))
    txout2 = CMutableTxOut(0.001*COIN,CScript([l_S2]))
    txout3 = CMutableTxOut(0.001*COIN,CScript([l_S3]))
    txout = [txout1, txout2, txout3]
    tx = CMutableTransaction([txin], txout)
    
    seckeyA = secKeys[0]
    seckeyB = secKeys[1]
    seckey3 = secKeys[2]
    
    # Sign Transaction
    sighash = SignatureHash(txin_l_S, tx, 0, SIGHASH_ALL)
    sigA = seckeyA.sign(sighash) + bytes([SIGHASH_ALL])
    sigB = seckeyB.sign(sighash) + bytes([SIGHASH_ALL])
    sig3 = seckey3.sign(sighash) + bytes([SIGHASH_ALL])
    
    # Verify Scripts 
    txin.scriptSig = CScript([sigA, seckeyA.pub, sigB, seckeyB.pub, seckey3.pub])
    VerifyScript(txin.scriptSig, txin_l_S, tx, 0, (SCRIPT_VERIFY_P2SH,))
      
    return l_S1, l_S2, l_S3, tx

def main():
    
    # Create Proxy connection 
    proxy_connection = bitcoin.rpc.Proxy()
    
    # Get new addresses
    address1 = proxy_connection.getnewaddress()
    address1 = str(address1)
    address2 = proxy_connection.getnewaddress()
    address2 = str(address2)
    seckeyA1 = proxy_connection.dumpprivkey(address1)
    seckeyB1 = proxy_connection.dumpprivkey(address2)
    
    #####-------------------------------#####
        ##### FUNDING TRANSACTION #####
    #####-------------------------------#####
    # Make initial transaction, from where the funding Transaction will be created.
    txin_redeemScript = CScript([seckeyA1.pub, OP_CHECKSIG])    
    txin_scriptPubKey = txin_redeemScript.to_p2sh_scriptPubKey()
    txin_p2sh_address = CBitcoinAddress.from_scriptPubKey(txin_scriptPubKey)
    value_in = 1000000
    txid = proxy_connection.sendtoaddress(txin_p2sh_address, value_in) 
    vout = 0
    proxy_connection.generate(1) 
    txin = CMutableTxIn(COutPoint(txid, vout))

    # Perform Funding Transaction
    r_S, tx_FT = fundingTx(seckeyA1, seckeyB1, txin, value_in, txin_redeemScript, txin_scriptPubKey)
    # Send Transaction to the node
    txin_scriptPubKey = r_S.to_p2sh_scriptPubKey()
    txin_p2sh_address = CBitcoinAddress.from_scriptPubKey(txin_scriptPubKey)
    ft_id = proxy_connection.sendtoaddress(txin_p2sh_address, value_in)
    #ft_id = proxy_connection.sendrawtransaction(tx_FT)
    print("Funding Transaction sent successfully to the node.")
    print(b2x(ft_id))
    print("\n")
    proxy_connection.generate(1)
        
    #####-------------------------------#####
        ##### COMMITMENT TRANSACTIONS #####
    #####-------------------------------#####
    
    third_a_keypairs, third_b_keypairs, devices_keypairs = generateKeys()
    value_in2 = proxy_connection.getrawtransaction(ft_id).vout[0].nValue
# =============================================================================
#     
#     #### COMMITMENT TRANSACTION A ####    
#     # Index of the commitment transaction. Should range between 0 and 9. 
#     tx_index0 = 0
#     l_SA, l_SB, l_S3, tx_commA0 = commitmentA(seckeyA1, seckeyB1, ft_id, tx_index0, devices_keypairs, third_a_keypairs, value_in2, r_S)
#     comm_A_id =proxy_connection.sendrawtransaction(tx_commA0) 
#     print("Commitment Transaction A sent successfully to the node.")
#     print(b2x(comm_A_id))
#     print("\n")
# =============================================================================
    
    #### COMMITMENT TRANSACTION B ####
    tx_index1 = 1
    l_SA_Comm, l_SB_Comm, tx_commB0, secKeys = commitmentB(seckeyA1, seckeyB1, ft_id, tx_index1, devices_keypairs, third_b_keypairs, value_in2, r_S)
    txin_scriptPubKey = l_SB_Comm.to_p2sh_scriptPubKey()
    txin_p2sh_address = CBitcoinAddress.from_scriptPubKey(txin_scriptPubKey)
    comm_B_id = proxy_connection.sendtoaddress(txin_p2sh_address, value_in2)
    proxy_connection.generate(1)
    #comm_B_id =proxy_connection.sendrawtransaction(tx_commB0) 
    print("Commitment Transaction B sent successfully to the node.")
    print(b2x(comm_B_id))
    print("\n")
    
# =============================================================================
#     #####-------------------------------#####
#         ##### CLOSING TRANSACTION #####
#     #####-------------------------------#####
#     
#     # Create key pairs for Closing Transaction
#     address3 = proxy_connection.getnewaddress()
#     address3 = str(address3)
#     address4 = proxy_connection.getnewaddress()
#     address4 = str(address4)
#     seckeyA2 = proxy_connection.dumpprivkey(address3)
#     seckeyB2 = proxy_connection.dumpprivkey(address4)       
# 
#     # Get funds from previous Funding Transaction
#     value_in2 = proxy_connection.getrawtransaction(ft_id).vout[0].nValue
#     txid = ft_id
#     vout = 0
#     txin = CMutableTxIn(COutPoint(txid, vout))
#                  
#     # Perform Closing Transaction
#     l_SA, l_SB, close_tx = closingTx(seckeyA1, seckeyB1, txin, seckeyA2, seckeyB2, value_in2, r_S)
# 
#     # Send Transaction to the node
#     ct_id = proxy_connection.sendrawtransaction(close_tx)
#     print("Closing Transaction sent successfully to the node.")
#     print(b2x(ct_id))
#     print("\n")
# =============================================================================
    
    #####-------------------------------#####
        ##### RECOVERY TRANSACTION #####
    #####-------------------------------#####  
    value_in = tx_commB0.vout[0].nValue
    txid = comm_B_id
    vout = 0
    txin = CMutableTxIn(COutPoint(txid, vout))

    
     # Perform recovery Tx. I use tx_index to search for the keys used for commitment_B
    l_S1, l_S2, l_S3, tx_recov = recoveryTx(secKeys, txin, tx_index1, devices_keypairs,third_a_keypairs, third_b_keypairs, value_in, l_SB_Comm)
# =============================================================================
#     txin_scriptPubKey = l_S3.to_p2sh_scriptPubKey()
#     txin_p2sh_address = CBitcoinAddress.from_scriptPubKey(txin_scriptPubKey)
#     recov_id = proxy_connection.sendtoaddress(txin_p2sh_address, value_in)
# =============================================================================
    recov_id = proxy_connection.sendrawtransaction(tx_recov)
    proxy_connection.generate(1)
    print("Recovery Transaction sent successfully to the node.")
    print(b2x(recov_id))
    print("\n")


if __name__ == '__main__':
    main()


