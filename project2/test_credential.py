#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Thu Apr 29 14:05:21 2021

@author: benoit
"""

import credential as c
import numpy as np

############################
# TEST GENKEY, SIG, VERIFY #
############################
def test_gen_sign_verify():
    msg1 = (1, c.Bn(1))
    msg2 = (2, c.Bn(2))
    msg3 = (3, c.Bn(3))
    msg4 = (4, c.Bn(4))
    msgs = [msg1, msg2, msg3, msg4]
    
    (sk, pk) = c.generate_key(msgs)
    
    sig: c.Signature = c.sign(sk, msgs)
    
    res = c.verify(pk, sig, msgs)

    assert res

def test_verify_neutral():
    msg1 = (1, c.Bn(1))
    msg2 = (2, c.Bn(2))
    msg3 = (3, c.Bn(3))
    msg4 = (4, c.Bn(4))
    msgs = [msg1, msg2, msg3, msg4]
    
    (sk,pk) = c.generate_key(msgs)
    
    (h, s) = c.sign(sk, msgs)
    
    res = c.verify(pk, (c.G1.neutral_element, s), msgs)

    assert not res
    
def test_verify_wrong_msg():
    att1 = (1, c.Bn(1))
    att2 = (2, c.Bn(2))
    att3 = (3, c.Bn(3))
    att4 = (4, c.Bn(4))
    att = [att1, att2, att3, att4]
    
    (sk,pk) = c.generate_key(att)
    
    msgs = [b'01', b'02', b'03', b'04']
    (h,s) = c.sign(sk,msgs)
    
    msgs = [b'01', b'01', b'03', b'04']
    res = c.verify(pk,(h,s),msgs)

    assert not res
    
def test_verify_wrong_sig():
    att1 = (1, c.Bn(1))
    att2 = (2, c.Bn(2))
    att3 = (3, c.Bn(3))
    att4 = (4, c.Bn(4))
    att = [att1, att2, att3, att4]
    
    (sk,pk) = c.generate_key(att)
    
    msgs = [b'01', b'02', b'03', b'04']
    (h,s) = c.sign(sk,msgs)
    
    sp = c.G1.generator() ** c.G1.order().random()
    while(sp.eq(s)):
        sp = c.G1.generator() ** c.G1.order().random()
    
    res = c.verify(pk,(h,sp),msgs)

    assert not res



##########################
# TEST ISSUANCE PROTOCOL #
##########################
def test_request():
    att1 = (1, c.Bn(1))
    att2 = (2, c.Bn(2))
    att3 = (3, c.Bn(3))
    att4 = (4, c.Bn(4))
    att = [att1, att2, att3, att4]
    
    (sk, pk) = c.generate_key(att)
    
    ua = [(0, att1[1]), (2, att3[1])]
    
    (request, t) = c.create_issue_request(pk, ua)

    assert request != None


def test_sign_request():
    att1 = (1, c.Bn(1))
    att2 = (2, c.Bn(2))
    att3 = (3, c.Bn(3))
    att4 = (4, c.Bn(4))
    att = [att1, att2, att3, att4]
    
    (sk,pk) = c.generate_key(att)
    
    ua = [(0, att1[1]), (2, att3[1])]
    ia = [(1, att2[1]), (3, att4[1])]
    
    (request,t) = c.create_issue_request(pk,ua)
    ((sig1,sig2),ai) = c.sign_issue_request(sk,pk,request,ia)

    assert sig1 != None and sig2 != None and ai != None


def test_sign_request_wrong_commit():
    att1 = (1, c.Bn(1))
    att2 = (2, c.Bn(2))
    att3 = (3, c.Bn(3))
    att4 = (4, c.Bn(4))
    att = [att1, att2, att3, att4]
    
    (sk,pk) = c.generate_key(att)
    
    ua = {0: att1, 2:att3}
    ia = {1: att2, 3:att4}
    
    ((com,pi),t) = c.create_issue_request(pk,ua)
    
    pi2 = c.hashlib.sha3_512(b'0') # Change hash of the commited value
    
    request = (com,pi2)
    res = c.sign_issue_request(sk,pk,request,ia)

    assert res == None

def test_obtain_cred_wrong_sig():
    att1 = (1, c.Bn(1))
    att2 = (2, c.Bn(2))
    att3 = (3, c.Bn(3))
    att4 = (4, c.Bn(4))
    att = [att1, att2, att3, att4]
    
    (sk,pk) = c.generate_key(att)
    
    ua = {0: att1, 2:att3}
    ia = {1: att2, 3:att4}
    
    (request,t) = c.create_issue_request(pk,ua)
    ((sig1,sig2),ai) = c.sign_issue_request(sk,pk,request,ia)
    
    sig1_n = c.G1.generator() ** c.G1.order().random()
    while(sig1_n.eq(sig1)):
        sig1_n = c.G1.generator() ** c.G1.order().random()
    
    res = c.obtain_credential(pk,((sig1_n,sig2),ai),t,ua)
    
    assert res == None


def test_obtain_cred():
    att1 = (1, c.Bn(1))
    att2 = (2, c.Bn(2))
    att3 = (3, c.Bn(3))
    att4 = (4, c.Bn(4))
    att = [att1, att2, att3, att4]
    
    (sk,pk) = c.generate_key(att)
    
    ua = {0: att1, 2: att3}
    ia = {1: att2, 3: att4}
    
    (request,t) = c.create_issue_request(pk,ua)
    ((sig1,sig2),ai) = c.sign_issue_request(sk,pk,request,ia)
    (sig,aj) = c.obtain_credential(pk,((sig1,sig2),ai),t,ua)
    
    assert sig != None and aj != None
    

#########################
# TEST SHOWING PROTOCOL #
#########################

def test_disclosure_proof():
    att1 = (1, c.Bn(1))
    att2 = (2, c.Bn(2))
    att3 = (3, c.Bn(3))
    att4 = (4, c.Bn(4))
    att = [att1, att2, att3, att4]
    
    (sk,pk) = c.generate_key(att)
    
    ua = {0: att1, 2:att3}
    ia = {1: att2, 3:att4}
    
    (request,t) = c.create_issue_request(pk,ua)
    ((sig1,sig2),ai) = c.sign_issue_request(sk,pk,request,ia)
    (sig,aj) = c.obtain_credential(pk,((sig1,sig2),ai),t,ua)
    
    hid_att = {0: att1}
    disProof = c.create_disclosure_proof(pk,(sig,aj),hid_att)
    
    assert disProof != None
 

def test_verify_disclosure_proof():
    att1 = (1, c.Bn(1))
    att2 = (2, c.Bn(2))
    att3 = (3, c.Bn(3))
    att4 = (4, c.Bn(4))
    att = [att1, att2, att3, att4]
    
    (sk,pk) = c.generate_key(att)
    
    ua = {0: att1, 2:att3}
    ia = {1: att2, 3:att4}
    
    (request,t) = c.create_issue_request(pk,ua)
    ((sig1,sig2),ai) = c.sign_issue_request(sk,pk,request,ia)
    (sig,aj) = c.obtain_credential(pk,((sig1,sig2),ai),t,ua)
    
    
    hid_att = ua
    disProof = c.create_disclosure_proof(pk,(sig,aj),hid_att)
    
    res = c.verify_disclosure_proof(pk,disProof,ia)
    
    assert res
    
def test_verify_disclosure_proof_bigNumbers():
    att1 = (1, c.Bn(100123))
    att2 = (2, c.Bn(201234))
    att3 = (3, c.Bn(10321))
    att4 = (4, c.Bn(31273))
    att = [att1,att2,att3,att4]
    
    (sk,pk) = c.generate_key(att)
    
    ua = {0: att1, 2:att3}
    ia = {1: att2, 3:att4}
    
    (request,t) = c.create_issue_request(pk,ua)
    ((sig1,sig2),ai) = c.sign_issue_request(sk,pk,request,ia)
    (sig,aj) = c.obtain_credential(pk,((sig1,sig2),ai),t,ua)
    
    
    hid_att = ua
    disProof = c.create_disclosure_proof(pk,(sig,aj),hid_att)
    
    res = c.verify_disclosure_proof(pk,disProof,ia)
    
    assert res