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
from bitcoin import core
from bitcoin import params
from bitcoin.core import *
from bitcoin.core.script import *
from blockchain import pushtx
from bitcoin import SelectParams
from bitcoin.core import b2x, lx, COIN, COutPoint, CMutableTxOut, CMutableTxIn, CMutableTransaction, Hash160
from bitcoin.core.script import *
from bitcoin.core.scripteval import VerifyScript, SCRIPT_VERIFY_P2SH, OP_NOP3
from bitcoin.wallet import CBitcoinAddress, CBitcoinSecret

SelectParams('regtest')


def fundingTx(seckeyA, seckeyB, pk_A_FT, pk_B_FT, address1, address2, txin, value_in): 

    # Generate redeem script and locking script
    r_S = CScript([OP_2, pk_A_FT, pk_B_FT, OP_2, OP_CHECKMULTISIG])
    r_S_Hash = Hash160(r_S)
    l_S = CScript([OP_HASH160,r_S_Hash, OP_EQUAL])
    
    # Create transaction with txin and txout 
    txout = CMutableTxOut(value_in-0.0005*COIN, CBitcoinAddress(address2).to_scriptPubKey())
    tx = CMutableTransaction([txin], [txout])

    # Create signatures
    sighash = SignatureHash(r_S, tx, 0, SIGHASH_ALL)
    sigA = seckeyA.sign(sighash) + bytes([SIGHASH_ALL])    
    sigB = seckeyB.sign(sighash) + bytes([SIGHASH_ALL])
    
    # Create unlocking script
    u_S = CScript([OP_0, sigA, sigB, r_S, l_S])

    # Generate transaction script 
    txin.scriptSig = CScript([sigA,sigB, r_S])
    
    # Verify multisignature
    VerifyScript(txin.scriptSig, l_S, tx, 0, (OP_CHECKMULTISIGVERIFY,))    
    return u_S, l_S, r_S, tx

def closingTx(txid,seckeyA, seckeyB, pk_A_Close, pk_B_Close, address1, address2, value_in2):
    
   # txid = tx_FT.GetTxid()
    vout = 0
    
    # Cambiar esto para que haya dos outputs. Y que utilice los coins de la funding transaction. 
    txin = CMutableTxIn(COutPoint(txid, vout))

    l_SA = CScript([OP_DUP, OP_HASH160, Hash160(pk_A_Close), OP_EQUALVERIFY, OP_CHECKSIG])
    l_SB = CScript([OP_DUP, OP_HASH160, Hash160(pk_B_Close), OP_EQUALVERIFY, OP_CHECKSIG])
    txout1 = CMutableTxOut(value_in2-0.0005*COIN-0.0005*COIN, CBitcoinAddress(address1).to_scriptPubKey())
    txout2 = CMutableTxOut(0.0005*COIN, CBitcoinAddress(address2).to_scriptPubKey())
    tx = CMutableTransaction([txin], [txout1,txout2])
    
    sighashA = SignatureHash(l_SA, tx, 0, SIGHASH_ALL)
    sighashB = SignatureHash(l_SB, tx, 0, SIGHASH_ALL)
    sigA = seckeyA.sign(sighashA) + bytes([SIGHASH_ALL])
    sigB = seckeyB.sign(sighashB) + bytes([SIGHASH_ALL])
    sigs = []
    sigs.append(sigA)
    sigs.append(sigB)
    
    u_SA = CScript([sigA, pk_A_Close])    
    u_SB = CScript([sigB, pk_B_Close])

    for sig in sigs:
        if (sig == sigA):
            seckey = seckeyA
            txin.scriptSig = CScript([sig, seckey.pub])
            VerifyScript(txin.scriptSig, l_SA, tx, 0, (SCRIPT_VERIFY_P2SH,))
            
        elif(sig == sigB):
            seckey = seckeyB
            txin.scriptSig = CScript([sig, seckey.pub])
            VerifyScript(txin.scriptSig, l_SB, tx, 0, (SCRIPT_VERIFY_P2SH,))
              
    return u_SA, u_SB, l_SA, l_SB, tx
            
def commitmentA(tx_FT,tx_index, devices_keypairs, third_a_keypairs, address1, address2):
    txid = tx_FT.GetTxid()
    vout = 0
    txin = CMutableTxIn(COutPoint(txid, vout))
    
    # PREGUNTA: QUÉ BITCOIN ADDRESS HAY QUE PONER !???
    txout = CMutableTxOut(0.001*COIN, CBitcoinAddress(address1).to_scriptPubKey())
    tx = CMutableTransaction([txin], [txout])
    
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

    sighashA = SignatureHash(l_SA, tx, 0, SIGHASH_ALL)
    sighashB = SignatureHash(l_SB, tx, 0, SIGHASH_ALL)
    sighash3 = SignatureHash(l_S3, tx, 0, SIGHASH_ALL)
    sigA = sk_A_a.sign(sighashA) + bytes([SIGHASH_ALL])
    sigB = sk_B_b.sign(sighashB) + bytes([SIGHASH_ALL])
    sig3_0 = sk_3_b_0.sign(sighash3) + bytes([SIGHASH_ALL])
    
    # Verification of l_SA, l_SB and l_S3.
    sigs = []
    sigs.append(sigA)
    sigs.append(sigB)
    sigs.append(sig3_0)
    for sig in sigs:
        if (sig == sigA):
            seckey = sk_A_a
            txin.scriptSig = CScript([sig, seckey.pub])
            VerifyScript(txin.scriptSig, l_SA, tx, 0, (SCRIPT_VERIFY_P2SH,))
            
        elif(sig == sigB):
            seckey = sk_B_b
            txin.scriptSig = CScript([sig, seckey.pub])
            VerifyScript(txin.scriptSig, l_SB, tx, 0, (SCRIPT_VERIFY_P2SH,))
        
        elif(sig == sig3_0):
            seckey = sk_3_b_0
            txin.scriptSig = CScript([0, sig])
            VerifyScript(txin.scriptSig, l_S3, tx, 0, (OP_CHECKMULTISIGVERIFY,))

    return l_SA, l_SB, l_S3, tx

def commitmentB(tx_FT,tx_index, devices_keypairs, third_b_keypairs, address1, address2):
    txid = tx_FT.GetTxid()
    vout = 0
    txin = CMutableTxIn(COutPoint(txid, vout))
    
    txout = CMutableTxOut(0.001*COIN, CBitcoinAddress(address2).to_scriptPubKey())
    tx = CMutableTransaction([txin], [txout]) 
    
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
        
    # Verify Scripts
    sighashA = SignatureHash(l_SA, tx, 0, SIGHASH_ALL)
    sigA = sk_A_b.sign(sighashA) + bytes([SIGHASH_ALL])
    
    sighashB = SignatureHash(l_SB, tx, 0, SIGHASH_ALL)    
    sigB = sk_B_a.sign(sighashB) + bytes([SIGHASH_ALL])
    sigC = sk_B_c.sign(sighashA) + bytes([SIGHASH_ALL])
    
    sigs = []
    sigs.append(sigA)
    sigs.append(sigB)
    
    for sig in sigs:
        if (sig == sigA):
            seckey = sk_A_b
            txin.scriptSig = CScript([sig, seckey.pub])
            # Does P2SH makes sense here?
            VerifyScript(txin.scriptSig, l_SA, tx, 0, (SCRIPT_VERIFY_P2SH,))
            
        if(sig == sigB):
            seckey = sk_B_a
            txin.scriptSig = CScript([sig, seckey.pub])
            VerifyScript(txin.scriptSig, l_SB, tx, 0, (SCRIPT_VERIFY_P2SH,))

    return l_SA, l_SB, tx, sigA, sigC
 
def recoveryTx(tx_commB,tx_index, l_SB, devices_keypairs,third_a_keypairs, third_b_keypairs, address2, sigA, sigC):
 
    txid = tx_commB.GetTxid()
    vout = 0
    txin = CMutableTxIn(COutPoint(txid, vout))
    txout = CMutableTxOut(0.001*COIN, CBitcoinAddress(address2).to_scriptPubKey())
    tx = CMutableTransaction([txin], [txout])
    
    # Devices keys and signatures
    pk_A_b = devices_keypairs[tx_index][0][1][0]
    sk_A_b = devices_keypairs[tx_index][0][1][1]
    sig_A_b = sigA
       
    pk_B_c = devices_keypairs[tx_index][1][2][0]
    sk_B_c = devices_keypairs[tx_index][1][2][1]
    sig_B_c = sigC
    
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
    
    # In 1
    u_S = CScript([sig_A_b, pk_A_b, sig_B_c, pk_B_c, pk_3_b_alpha])   
    
    # Out 1
    l_S1 = CScript([OP_DUP, OP_HASH160, Hash160(pk_A_rc), OP_EQUALVERIFY, OP_CHECKSIG])     
    sighashA = SignatureHash(l_S1, tx, 0, SIGHASH_ALL)
    sig_A_rc = sk_A_rc.sign(sighashA) + bytes([SIGHASH_ALL])    
    
    u_S1 = CScript([sig_A_rc, pk_A_rc])
    
    # Out 2
    l_S2 = CScript([OP_DUP, OP_HASH160, Hash160(pk_3_b_omega), OP_EQUALVERIFY, OP_CHECKSIG])
    sighash = SignatureHash(l_S2, tx, 0, SIGHASH_ALL)
    sig_3_b_omega = sk_3_b_omega.sign(sighash) + bytes([SIGHASH_ALL])  

    l_S3 = CScript([OP_1, pk_3_a_0, pk_3_a_1, OP_2, OP_CHECKMULTISIG, OP_DROP])     

    # Verify Scripts 
    txin.scriptSig = CScript([sig_A_rc, sk_A_rc.pub]) 
    VerifyScript(txin.scriptSig, l_S1, tx, 0, (SCRIPT_VERIFY_P2SH,))
    
    txin.scriptSig = CScript([sig_3_b_omega, sk_3_b_omega.pub]) 
    VerifyScript(txin.scriptSig, l_S2, tx, 0, (SCRIPT_VERIFY_P2SH,))
    
    return l_S1, u_S1, l_S2, l_S3, tx
    
# Generate a random string of fixed length
def randomString(stringLength=30):
    letters = string.ascii_lowercase
    return ''.join(random.choice(letters) for i in range(stringLength)).encode('utf-8')

def main():
    
    # Create Proxy connection 
    proxy_connection = bitcoin.rpc.Proxy()
    
    # Get new addresses
    address1 = proxy_connection.getnewaddress()
    address1 = str(address1)
    address2 = proxy_connection.getnewaddress()
    address2 = str(address2)
    
    address3 = proxy_connection.getnewaddress()
    address3 = str(address3)
    
    #### FUNDING TRANSACTION ####
    # Get initial UTXO from wallet to fund the Funding Transaction
    unspent = sorted(proxy_connection.listunspent(0), key=lambda x: hash(x['amount']))
    txin = [CMutableTxIn(unspent[-1]['outpoint'])][0]
    value_in = unspent[-1]['amount']
    
  
    # Create key pairs for Funding Transaction
    hA1 = hashlib.sha256(b'correct horse battery staple').digest()
    hB1 = hashlib.sha256(b'sdfdsfdsdfsd').digest()
    seckeyA1 = CBitcoinSecret.from_secret_bytes(hA1)
    seckeyB1 = CBitcoinSecret.from_secret_bytes(hB1)
    pk_A_FT = seckeyA1.pub
    pk_B_FT = seckeyB1.pub
    
    # Perform Funding Transaction
    u_S, l_S, r_S, tx_FT = fundingTx(seckeyA1, seckeyB1, pk_A_FT, pk_B_FT, address1, address2, txin,value_in)

    # Sign raw transaction and send it to the connected node
    r = proxy_connection.signrawtransaction(tx_FT)
    tx = r['tx']
    ft_id =proxy_connection.sendrawtransaction(tx)
    print("Funding Transaction ID")
    print(b2lx(ft_id))
    print("\n")
    
    # Generate block to confirm transaction
    proxy_connection.generate(1)
    
    # Verify that transaction has been added to the block. Need to review this (!!!)
    nwInfo = proxy_connection.getmininginfo()
    print("Mining info")
    print(nwInfo)
    print("\n")
    
    ##### CLOSING TRANSACTION #####
    # Create key pairs for Closing Transaction
    hA2 = hashlib.sha256(b'kjhgkhkq').digest()
    hB2 = hashlib.sha256(b'asdfawei').digest()
    seckeyA2 = CBitcoinSecret.from_secret_bytes(hA2)
    seckeyB2 = CBitcoinSecret.from_secret_bytes(hB2)        
    pk_A_Close = seckeyA2.pub
    pk_B_Close = seckeyB2.pub
    
    # Get funds from previous Funding Transaction
    unspent = sorted(proxy_connection.listunspent(0), key=lambda x: hash(x['amount']))
    value_in2 = 0    
    for i in range(len(unspent)):         
        if(str(unspent[i]['outpoint'])==str(b2lx(ft_id)+":0")):
            value_in2 = unspent[i]['amount']
            
    # Perform Closing Transaction
    u_SA, u_SB, l_SA, l_SB, close_tx = closingTx(ft_id ,seckeyA2, seckeyB2, pk_A_Close, pk_B_Close, address1, address2, value_in2)

    # Sign raw transaction and send it to the connected node
    r = proxy_connection.signrawtransaction(close_tx)
    tx = r['tx']
    close_id =proxy_connection.sendrawtransaction(tx)
    
    #### COMMITMENT TRANSACTIONS ####
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
     
    #### COMMITMENT TRANSACTION A ####
    # Index of the commitment transaction. Should range between 0 and 9. 
    tx_index = 0
    l_SA, l_SB, l_S3, tx_commA = commitmentA(tx_FT,tx_index, devices_keypairs, third_a_keypairs, address1, address2)
     
    #### COMMITMENT TRANSACTION B #### 
    tx_index = 1
    l_SA, l_SB, tx_commB, sigA, sigC = commitmentB(tx_FT,tx_index, devices_keypairs, third_b_keypairs, address1, address2)
     
    #### RECOVERY TRANSACTION #### 
    
    # Key pairs for A transacting with the Third Parties
    
    # Perform recovery Tx. I use tx_index to search for the keys used for commitment_B
    l_S1, u_S1, l_S2, l_S3, tx_recov = recoveryTx(tx_commB,tx_index,l_SB, devices_keypairs,third_a_keypairs, third_a_keypairs, address2, sigA, sigC)

if __name__ == '__main__':
    main()


