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
from bitcoin import core
from blockchain import pushtx
from bitcoin import SelectParams
from bitcoin.core import b2x, lx, COIN, COutPoint, CMutableTxOut, CMutableTxIn, CMutableTransaction, Hash160
from bitcoin.core.script import *
from bitcoin.core.scripteval import VerifyScript, SCRIPT_VERIFY_P2SH, OP_NOP3
from bitcoin.wallet import CBitcoinAddress, CBitcoinSecret



def fundingTx(seckeyA, seckeyB, pk_A_FT, pk_B_FT): 
    print("FUNDING TRANSACTION" +'\n')

    r_S = CScript([OP_2, pk_A_FT, pk_B_FT, OP_2, OP_CHECKMULTISIG])
    r_S_Hash = Hash160(r_S)
    l_S = CScript([OP_HASH160,r_S_Hash, OP_EQUAL])
    
    txid = lx('bff785da9f8169f49be92fa95e31f0890c385bfb1bd24d6b94d7900057c617ae')
    
    vout = 0
    
    txin = CMutableTxIn(COutPoint(txid, vout))
    txout = CMutableTxOut(0.0005*COIN, CBitcoinAddress('323uf9MgLaSn9T7vDaK1cGAZ2qpvYUuqSp').to_scriptPubKey())
    
    tx = CMutableTransaction([txin], [txout])


    sighash = SignatureHash(r_S, tx, 0, SIGHASH_ALL)

    sigA = seckeyA.sign(sighash) + bytes([SIGHASH_ALL])
    
    sigB = seckeyB.sign(sighash) + bytes([SIGHASH_ALL])
    
    
    
    
    u_S = CScript([OP_0, sigA, sigB, r_S, l_S])
    
    print("SIGNATURE A: ",b2x(sigA)+ '\n')
    print("SIGNATURE B: ",b2x(sigB)+ '\n')
    print("REDEEM SCRIPT:",'\n',b2x(r_S)+'\n')
    print("LOCKING SCRIPT: ",b2x(l_S)+'\n')
    print("UNLOCKING SCRIPT: ", b2x(u_S) + '\n')

    txin.scriptSig = CScript([sigA,sigB, r_S])
    if(VerifyScript(txin.scriptSig, l_S, tx, 0, (OP_CHECKMULTISIGVERIFY,)) == None):
        print("VERIFICATION = TRUE"+'\n')
    
    return u_S, l_S, r_S, tx, txin

def closingTx(tx_FT,seckeyA, seckeyB, pk_A_Close, pk_B_Close):
   # print("CLOSING TRANSACTION" +'\n')
    
    txid = tx_FT.GetTxid()
    vout = 0
    txin = CMutableTxIn(COutPoint(txid, vout))

    l_SA = CScript([OP_DUP, OP_HASH160, Hash160(pk_A_Close), OP_EQUALVERIFY, OP_CHECKSIG])
    l_SB = CScript([OP_DUP, OP_HASH160, Hash160(pk_B_Close), OP_EQUALVERIFY, OP_CHECKSIG])
    txout = CMutableTxOut(0.001*COIN, CBitcoinAddress('1C7zdTfnkzmr13HfA2vNm5SJYRK6nEKyq8').to_scriptPubKey())
    tx = CMutableTransaction([txin], [txout])
    
    
    sighashA = SignatureHash(l_SA, tx, 0, SIGHASH_ALL)
    sighashB = SignatureHash(l_SB, tx, 0, SIGHASH_ALL)
    sigA = seckeyA.sign(sighashA) + bytes([SIGHASH_ALL])
    sigB = seckeyB.sign(sighashB) + bytes([SIGHASH_ALL])
    sigs = []
    sigs.append(sigA)
    sigs.append(sigB)
    
    u_SA = CScript([sigA, pk_A_Close])    
    u_SB = CScript([sigB, pk_B_Close])
    
    print("SIGNATURE A: ", b2x(sigA)+'\n')
    print("PUBLIC KEY A: ", b2x(pk_A_Close)+'\n')
    print("LOCKING SCRIPT A: ",b2x(l_SA)+'\n')
    print("UNLOCKING SCRIPT A: ",b2x(u_SA)+'\n')
    print("SIGNATURE B: ", b2x(sigB)+'\n')
    print("PUBLIC KEY B: ", b2x(pk_B_Close)+'\n')
    print("LOCKING SCRIPT B: ",b2x(l_SB)+'\n')
    print("UNLOCKING SCRIPT B: ",b2x(u_SB)+'\n')
    
    for sig in sigs:
        if (sig == sigA):
            seckey = seckeyA
            txin.scriptSig = CScript([sig, seckey.pub])
            if(VerifyScript(txin.scriptSig, l_SA, tx, 0, (SCRIPT_VERIFY_P2SH,)) == None):
                print("VERIFICATION A = TRUE"+'\n')
            
        elif(sig == sigB):
            seckey = seckeyB
            txin.scriptSig = CScript([sig, seckey.pub])
            if(VerifyScript(txin.scriptSig, l_SB, tx, 0, (SCRIPT_VERIFY_P2SH,)) == None):
                print("VERIFICATION B = TRUE"+'\n')
              
    return u_SA, u_SB, l_SA, l_SB, tx
            
def commitmentA(tx_FT, keyPairs):
    print("COMMITMENT TRANSACTION PUBLISHABLE BY A"+'\n')
    txid = tx_FT.GetTxid()
    vout = 0
    txin = CMutableTxIn(COutPoint(txid, vout))
    
    # PREGUNTA: QUÉ BITCOIN ADDRESS HAY QUE PONER !???
    txout = CMutableTxOut(0.001*COIN, CBitcoinAddress('1C7zdTfnkzmr13HfA2vNm5SJYRK6nEKyq8').to_scriptPubKey())
    tx = CMutableTransaction([txin], [txout])
    
    
    pk_A_a = keyPairs['A'][0][0]
    sk_A_a = keyPairs['A'][0][1]
    pk_B_b = keyPairs['B'][1][0]
    sk_B_b = keyPairs['B'][1][1]
    pk_A_c = keyPairs['A'][2][0]
   # l_SA = CScript([OP_DUP, OP_HASH160, Hash160(pk_A_Close), OP_EQUALVERIFY, OP_CHECKSIG])
    l_SA = CScript([OP_DUP, OP_HASH160,Hash160(pk_A_a), OP_EQUALVERIFY, OP_CHECKSIG])
    l_SA1 = CScript([OP_NOP3, OP_DROP, l_SA])
    l_SA2 = CScript([OP_DUP, OP_HASH160, Hash160(pk_B_b), OP_EQUALVERIFY, OP_CHECKSIG, OP_DROP])
    l_SA3 = CScript([OP_DUP, OP_HASH160, Hash160(pk_A_c), OP_EQUALVERIFY, OP_CHECKSIG])
    
    # FALTA LA W !!!! PREGUNTAR QUÉ ES
    l_SA = CScript([OP_IF, l_SA1, OP_ELSE, l_SA2, l_SA3, OP_ENDIF])   
    l_SB = CScript([OP_DUP, OP_HASH160, Hash160(pk_B_b), OP_EQUALVERIFY, OP_CHECKSIG])
    
    # FALTA EL OUT 3 !!!!!
    l_S3 = ""
    
    sighashA = SignatureHash(l_SA, tx, 0, SIGHASH_ALL)
    sighashB = SignatureHash(l_SB, tx, 0, SIGHASH_ALL)
    sigA = sk_A_a.sign(sighashA) + bytes([SIGHASH_ALL])
    sigB = sk_B_b.sign(sighashB) + bytes([SIGHASH_ALL])
    txin.scriptSig = CScript([sigA, pk_A_a])
    

    print("HASH pk_A_a: ", b2x(Hash160(pk_A_a))+'\n')
    print("HASH pk_B_b: ", b2x(Hash160(pk_B_b))+'\n')
    print("HASH  pk_A_c: ", b2x(Hash160(pk_A_c))+'\n')
    print("LOCKING SCRIPT A: ",b2x(l_SA)+'\n')
    print("LOCKING SCRIPT b: ",b2x(l_SB)+'\n')
    
    sigs = []
    sigs.append(sigA)
    sigs.append(sigB)
    VerifyScript(txin.scriptSig, l_SA, tx, 0, (SCRIPT_VERIFY_P2SH,))
    for sig in sigs:
        if (sig == sigA):
            seckey = sk_A_a
            txin.scriptSig = CScript([sig, seckey.pub])
            if(VerifyScript(txin.scriptSig, l_SA, tx, 0, (SCRIPT_VERIFY_P2SH,)) == None):
                print("VERIFICATION A = TRUE"+'\n')
            
        elif(sig == sigB):
            seckey = sk_B_b
            txin.scriptSig = CScript([sig, seckey.pub])
            if(VerifyScript(txin.scriptSig, l_SB, tx, 0, (SCRIPT_VERIFY_P2SH,)) == None):
                print("VERIFICATION B = TRUE"+'\n')

    return l_SA, l_SB, l_S3, tx

def commitmentB(tx_FT, keyPairs):
    print("COMMITMENT TRANSACTION PUBLISHABLE BY B"+'\n')
    txid = tx_FT.GetTxid()
    vout = 0
    txin = CMutableTxIn(COutPoint(txid, vout))
    
    # PREGUNTA: QUÉ BITCOIN ADDRESS HAY QUE PONER ???
    txout = CMutableTxOut(0.001*COIN, CBitcoinAddress('1C7zdTfnkzmr13HfA2vNm5SJYRK6nEKyq8').to_scriptPubKey())
    tx = CMutableTransaction([txin], [txout]) 
    
    pk_A_b = keyPairs['A'][1][0]
    sk_A_b = keyPairs['A'][1][1]
    pk_B_a = keyPairs['B'][0][0]
    sk_B_a = keyPairs['B'][0][1]
    pk_B_c = keyPairs['B'][2][0]
    sk_B_c = keyPairs['B'][2][1]
    pk_B_3rd_0 = keyPairs['B'][3][0]
    pk_B_3rd_K = keyPairs['B'][4][0]
    
   # l_SA = CScript([OP_DUP, OP_HASH160, Hash160(pk_A_Close), OP_EQUALVERIFY, OP_CHECKSIG])
    l_SB = CScript([OP_DUP, OP_HASH160,Hash160(pk_B_a), OP_EQUALVERIFY, OP_CHECKSIG])
    l_SB1 = CScript([OP_NOP3, OP_DROP, l_SB])
    l_SB2 = CScript([OP_1, pk_B_3rd_0, pk_B_3rd_K, OP_CHECKMULTISIG, OP_DROP])
    l_SB3 = CScript([OP_DUP, OP_HASH160, Hash160(pk_B_c), OP_EQUALVERIFY, OP_CHECKSIG, OP_DROP])
    l_SB4 = CScript([OP_DUP, OP_HASH160, Hash160(pk_A_b), OP_EQUALVERIFY, OP_CHECKSIG])
    
    # FALTA LA W !!!! PREGUNTAR QUÉ ES
    l_SB = CScript([OP_IF, l_SB1, OP_ELSE, l_SB2, l_SB3, l_SB4, OP_ENDIF])   
    l_SA = CScript([OP_DUP, OP_HASH160, Hash160(pk_A_b), OP_EQUALVERIFY, OP_CHECKSIG])
        
    sighashA = SignatureHash(l_SA, tx, 0, SIGHASH_ALL)
    sighashB = SignatureHash(l_SB, tx, 0, SIGHASH_ALL)
    sigA = sk_A_b.sign(sighashA) + bytes([SIGHASH_ALL])
    sigB = sk_B_a.sign(sighashB) + bytes([SIGHASH_ALL])
    sigC = sk_B_c.sign(sighashA) + bytes([SIGHASH_ALL])
    
    sigs = []
    sigs.append(sigA)
    sigs.append(sigB)
    
    print("HASH pk_B_a: ", (Hash160(pk_B_a))) 
    print("HASH pk_B_a: ", b2x(Hash160(pk_B_a))+'\n')   
    print("pk_B_3rd_0: ", b2x(pk_B_3rd_0)+'\n')
    print("pk_B_3rd_K: ", b2x(pk_B_3rd_K)+'\n')
    print("HASH pk_B_c: ", b2x(Hash160(pk_B_c))+'\n')
    print("HASH pk_A_b: ", b2x(Hash160(pk_A_b))+'\n')
    print("LOCKING SCRIPT B: ",b2x(l_SB)+'\n')
    print("HASH pk_A_b: ", b2x(Hash160(pk_A_b))+'\n')
    print("LOCKING SCRIPT A: ",b2x(l_SA)+'\n')
    
    for sig in sigs:
        if (sig == sigA):
            seckey = sk_A_b
            txin.scriptSig = CScript([sig, seckey.pub])
            if(VerifyScript(txin.scriptSig, l_SA, tx, 0, (SCRIPT_VERIFY_P2SH,)) == None):
                print("VERIFICATION A = TRUE"+'\n')
            
        elif(sig == sigB):
            seckey = sk_B_a
            txin.scriptSig = CScript([sig, seckey.pub])
            if(VerifyScript(txin.scriptSig, l_SB, tx, 0, (SCRIPT_VERIFY_P2SH,)) == None):
                print("VERIFICATION B = TRUE"+'\n')

    return l_SA, l_SB, tx, sigA, sigC
 
def recoveryTx(tx_commB, l_SB_commB, keyPairs, sigA, sigC):
    
    print("RECOVERY TRANSACTION" +'\n')
    
    
    txid = tx_commB.GetTxid()
    vout = 0
    txin = CMutableTxIn(COutPoint(txid, vout))
    # PREGUNTA: QUÉ BITCOIN ADDRESS HAY QUE PONER !???
    txout = CMutableTxOut(0.001*COIN, CBitcoinAddress('1C7zdTfnkzmr13HfA2vNm5SJYRK6nEKyq8').to_scriptPubKey())
    tx = CMutableTransaction([txin], [txout])
    
    sig_A_b = sigA
    sig_B_c = sigC
    
    
    pk_B_b = keyPairs['B'][1][0]
    sk_B_b = keyPairs['B'][1][1]
    pk_A_c = keyPairs['A'][2][0]
    
    pk_A_rc = keyPairs['A'][5][0]
    sk_A_rc = keyPairs['A'][5][1]
    pk_3rd_a_0 = keyPairs['A'][3][0]
    pk_3rd_a_K = keyPairs['A'][3][0]
    
    pk_A_b = keyPairs['A'][1][0]
    sk_A_b = keyPairs['A'][1][1]
    pk_B_c = keyPairs['B'][2][0]
    sk_B_c = keyPairs['B'][2][1]
    pk_3rd_b_alpha = keyPairs['3'][1][0]
    pk_3rd_b_beta = keyPairs['3'][2][0]
    
    # METER PK_3_b !!!!!!!
    u_S1 = CScript([sig_A_b, pk_A_b, sig_B_c, pk_B_c, pk_3rd_b_alpha])
    
    
    print("OUTPUT 1"+'\n')
    l_S1 = CScript([OP_DUP, OP_HASH160, Hash160(pk_A_rc), OP_EQUALVERIFY, OP_CHECKSIG])
   
    sighashA = SignatureHash(l_S1, tx, 0, SIGHASH_ALL)
    sig_A_rc = sk_A_rc.sign(sighashA) + bytes([SIGHASH_ALL])
    u_S1 = CScript([sig_A_rc, pk_A_rc])
    print("LOCKING SCRIPT A: ", b2x(l_S1)+'\n')
    print("UNLOCKING SCRIPT A: ", b2x(u_S1)+'\n')
    
    print("OUTPUT 2"+'\n')
    l_S2 = CScript([OP_DUP, OP_HASH160, Hash160(pk_3rd_b_beta), OP_EQUALVERIFY, OP_CHECKSIG])
    print("LOCKING SCRIPT 3rd PARTY b: ", b2x(l_S2)+'\n')
    
    print("OUTPUT 3"+'\n')
    l_S3 = CScript([OP_1, pk_3rd_a_0, pk_3rd_a_K, OP_CHECKMULTISIG, OP_DROP])
    print("LOCKING SCRIPT 3rd PARTY a: ", b2x(l_S3)+'\n')
    
    return l_S1, u_S1, l_S2, l_S3
    
def randomString(stringLength=30):
    """Generate a random string of fixed length """
    letters = string.ascii_lowercase
    return ''.join(random.choice(letters) for i in range(stringLength)).encode('utf-8')

def main():
    
    
    hA1 = hashlib.sha256(b'correct horse battery staple').digest()
    hB1 = hashlib.sha256(b'sdfdsfdsdfsd').digest()
    seckeyA1 = CBitcoinSecret.from_secret_bytes(hA1)
    seckeyB1 = CBitcoinSecret.from_secret_bytes(hB1)
    pk_A_FT = seckeyA1.pub
    pk_B_FT = seckeyB1.pub
    u_S, l_S, r_S, tx_FT, txin = fundingTx(seckeyA1, seckeyB1, pk_A_FT, pk_B_FT)
    
    
    hA2 = hashlib.sha256(b'correct horse battery staple').digest()
    hB2 = hashlib.sha256(b'asdfawei').digest()
    seckeyA2 = CBitcoinSecret.from_secret_bytes(hA2)
    seckeyB2 = CBitcoinSecret.from_secret_bytes(hB2)
    
    pk_A_Close = seckeyA2.pub
    pk_B_Close = seckeyB2.pub
    
    u_SA, u_SB, l_SA, l_SB, close_tx = closingTx(tx_FT,seckeyA2, seckeyB2, pk_A_Close, pk_B_Close)

    keyPairs = dict()
    
    index1 = ['A','B','3']
    index2 = ['a','b','c','3rd_0','3rd_K', 'rc']
    for i in index1:
        keys = []
        for j in index2:
            h = hashlib.sha256(randomString()).digest()
            sk = CBitcoinSecret.from_secret_bytes(h)
            pk = sk.pub
            keys.append([pk, sk])
        keyPairs[i] = keys
    
    l_SA, l_SB, l_S3, tx_commA = commitmentA(tx_FT, keyPairs)
    l_SA, l_SB, tx_commB, sigA, sigC = commitmentB(tx_FT, keyPairs)
    l_S1, u_S1, l_S2, l_S3 = recoveryTx(tx_commB,l_SB, keyPairs, sigA, sigC)
    
    #pushtx.pushtx(b2x(tx_FT.serialize()))

    
    
    
   
if __name__ == '__main__':
    main()


