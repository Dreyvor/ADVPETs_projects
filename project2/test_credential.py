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
    att1 = c.Bn(1)
    att2 = c.Bn(2)
    att = np.array([att1,att2]).tolist()
    
    (sk,pk) = c.generate_key(att)
    
    msgs = np.array([b'01',b'02']).tolist()
    (h,s) = c.sign(sk,msgs)
    
    res = c.verify(pk,(h,s),msgs)

    assert res
    
def test_verify_neutral():
    att1 = c.Bn(1)
    att2 = c.Bn(2)
    att = np.array([att1,att2]).tolist()
    
    (sk,pk) = c.generate_key(att)
    
    msgs = np.array([b'01',b'02']).tolist() 
    (h,s) = c.sign(sk,msgs)
    
    res = c.verify(pk,(c.G1.neutral_element,s),msgs)

    assert not res
    
def test_verify_wrong_msg():
    att1 = c.Bn(1)
    att2 = c.Bn(2)
    
    att = np.array([att1,att2]).tolist()
    
    (sk,pk) = c.generate_key(att)
    
    msgs = np.array([b'01',b'02']).tolist() 
    (h,s) = c.sign(sk,msgs)
    
    msgs = np.array([b'01',b'03']).tolist()
    res = c.verify(pk,(h,s),msgs)

    assert not res
    
def test_verify_wrong_sig():
    att1 = c.Bn(1)
    att2 = c.Bn(2)
    att = np.array([att1,att2]).tolist()
    
    (sk,pk) = c.generate_key(att)
    
    msgs = np.array([b'01',b'02']).tolist() 
    (h,s) = c.sign(sk,msgs)
    
    sp = c.get_random_G1_different_from(s)
    
    res = c.verify(pk,(h,sp),msgs)

    assert not res
        
##########################
# TEST ISSUANCE PROTOCOL #
##########################
def test_request():
    att1 = c.Bn(1)
    att2 = c.Bn(2)
    att = np.array([att1,att2]).tolist()
    
    (sk,pk) = c.generate_key(att)
    
    ua = {0: att1, 1: att2}
    
    (request,t) = c.create_issue_request(pk,ua)

    assert request != None

def test_sign_request():
    att1 = c.Bn(1)
    att2 = c.Bn(2)
    att = np.array([att1,att2]).tolist()
    
    (sk,pk) = c.generate_key(att)
    
    ua = {0: att1}
    ia = {1: att2}
    
    (request,t) = c.create_issue_request(pk,ua)
    (sig1,sig2,ai) = c.sign_issue_request(sk,pk,request,ia)

    assert sig1 != None and sig2 != None and ai != None
    
def test_sign_request_wrong_commit():
    att1 = c.Bn(1)
    att2 = c.Bn(2)
    att = np.array([att1,att2]).tolist()
    
    (sk,pk) = c.generate_key(att)
    
    ua = {0: att1}
    ia = {1: att2}
    
    ((com,pi),t) = c.create_issue_request(pk,ua)
    
    pi2 = c.hashlib.sha3_512(b'0') # Change hash of the commited value
    
    request = (com,pi2)
    res = c.sign_issue_request(sk,pk,request,ia)

    assert res == None

def test_obtain_cred():
    att1 = c.Bn(1)
    att2 = c.Bn(2)
    att = np.array([att1,att2]).tolist()
    
    (sk,pk) = c.generate_key(att)
    
    ua = {0: att1}
    ia = {1: att2}
    
    (request,t) = c.create_issue_request(pk,ua)
    (sig1,sig2,ai) = c.sign_issue_request(sk,pk,request,ia)
    (sig,aj) = c.obtain_credential(pk,(sig1,sig2,ai),t,ua)
    
    assert sig != None and aj != None

def test_obtain_cred_wrong_sig():
    att1 = c.Bn(1)
    att2 = c.Bn(2)
    att = np.array([att1,att2]).tolist()
    
    (sk,pk) = c.generate_key(att)
    
    ua = {0: att1}
    ia = {1: att2}
    
    (request,t) = c.create_issue_request(pk,ua)
    (sig1,sig2,ai) = c.sign_issue_request(sk,pk,request,ia)
    
    sig1 = c.get_random_G1_different_from(sig1)
    res = c.obtain_credential(pk,(sig1,sig2,ai),t,ua)
    
    assert res == None
    