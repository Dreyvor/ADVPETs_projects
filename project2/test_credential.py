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
    msg1 = (1, c.Bn(1))
    msg2 = (2, c.Bn(2))
    msg3 = (3, c.Bn(3))
    msg4 = (4, c.Bn(4))
    msgs = [msg1, msg2, msg3, msg4]
    
    (sk,pk) = c.generate_key(msgs)
    
    (h,s) = c.sign(sk,msgs)
    
    msgs[1] = (2, c.Bn(1))
    res = c.verify(pk,(h,s),msgs)

    assert not res
    
def test_verify_wrong_sig():
    msg1 = (1, c.Bn(1))
    msg2 = (2, c.Bn(2))
    msg3 = (3, c.Bn(3))
    msg4 = (4, c.Bn(4))
    msgs = [msg1, msg2, msg3, msg4]
    
    (sk, pk) = c.generate_key(msgs)
    
    (h, s) = c.sign(sk, msgs)
    
    sp = c.G1.generator() ** c.G1.order().random()
    while(sp.eq(s)):
        sp = c.G1.generator() ** c.G1.order().random()
    
    res = c.verify(pk, (h, sp), msgs)

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
    
    ((challenge, zkp), t) = c.create_issue_request(pk, ua)

    assert challenge != None and zkp != None and t != None


def test_sign_request():
    att = {}
    att['a'] = (1, c.Bn(1))
    att['b'] = (2, c.Bn(2))
    att['c'] = (3, c.Bn(3))
    att['d'] = (4, c.Bn(4))
    
    (sk, pk) = c.generate_key(att.values())
    
    ua_str = ['a', 'c']
    ua = [att[c] for c in ua_str]

    ia_str = ['b', 'd']
    ia = [att[c] for c in ia_str]
    
    (request, t) = c.create_issue_request(pk, ua)
    (sig1, sig2) = c.sign_issue_request(sk, pk, request, ia_str, att)

    assert sig1 != None and sig2 != None


def test_sign_request_wrong_zkp():
    att = {}
    att['a'] = (1, c.Bn(1))
    att['b'] = (2, c.Bn(2))
    att['c'] = (3, c.Bn(3))
    att['d'] = (4, c.Bn(4))
    
    (sk, pk) = c.generate_key(att.values())
    
    ua_str = ['a', 'c']
    ua = [att[c] for c in ua_str]

    ia_str = ['b', 'd']
    ia = [att[c] for c in ia_str]

    wrong_choice_str = ['a', 'c', 'd']
    wrong_choice_list = [att[c] for c in wrong_choice_str]
    
    ((commitment, zkp), t) = c.create_issue_request(pk, ua)
    
    zkp2 = c.generate_zkp_prover_side(pk, t, wrong_choice_list, commitment)
    
    request = (commitment, zkp2)
    res = c.sign_issue_request(sk, pk, request, ia_str, att)

    assert res == None

def test_obtain_cred_wrong_sig():
    att = {}
    att['a'] = (1, c.Bn(1))
    att['b'] = (2, c.Bn(2))
    att['c'] = (3, c.Bn(3))
    att['d'] = (4, c.Bn(4))

    (sk,pk) = c.generate_key(att.values())
    
    ua_str = ['a', 'c']
    ua = [att[c] for c in ua_str]

    ia_str = ['b', 'd']
    ia = [att[c] for c in ia_str]
    
    (request, t) = c.create_issue_request(pk, ua)
    (sig1, sig2) = c.sign_issue_request(sk, pk, request, ia_str, att)
    
    sig1_n = c.G1.generator() ** c.G1.order().random()
    while(sig1_n.eq(sig1)):
        sig1_n = c.G1.generator() ** c.G1.order().random()
    
    res = c.obtain_credential(pk, (sig1_n, sig2), t, ua)
    
    assert res == None


def test_obtain_cred():
    subscription_map = {}
    subscription_map['a'] = (1, c.Bn(1))
    subscription_map['b'] = (2, c.Bn(2))
    subscription_map['c'] = (3, c.Bn(3))
    subscription_map['d'] = (4, c.Bn(4))

    attributes = list(subscription_map.values())

    (sk, pk) = c.generate_key(attributes)
    
    ua_str = ['a', 'd']
    ua = [subscription_map[c] for c in ua_str]

    ia_str = ['b', 'c']
    ia = [subscription_map[c] for c in ia_str]
    
    (request, t) = c.create_issue_request(pk, ua)
    assert(request != None and t != None)
    response = c.sign_issue_request(sk, pk, request, ia_str, subscription_map)
    assert(response != None)
       
    anon_cred = c.obtain_credential(pk, response, t, attributes)
    
    assert anon_cred != None
    

#########################
# TEST SHOWING PROTOCOL #
#########################

def test_create_verify_disclosure_proof():
    subscription_map = {}
    subscription_map['a'] = (1, c.Bn(1))
    subscription_map['b'] = (2, c.Bn(2))
    subscription_map['c'] = (3, c.Bn(3))
    subscription_map['d'] = (4, c.Bn(4))

    attributes = list(subscription_map.values())

    (sk,pk) = c.generate_key(attributes)
    
    ua_str = ['a', 'd']
    ua = [subscription_map[c] for c in ua_str]

    ia_str = ['b', 'c']
    ia = [subscription_map[c] for c in ia_str]
    
    (request, t) = c.create_issue_request(pk, ua)
    response = c.sign_issue_request(sk, pk, request, ia_str, subscription_map)
    anon_cred = c.obtain_credential(pk, response, t, attributes)
    assert anon_cred != None
    
    hid_att_str = ['b', 'a', 'd']
    hid_att = [subscription_map[e] for e in hid_att_str]

    # Create disclosure proof
    disProof = c.create_disclosure_proof(pk, anon_cred, hid_att)
    assert disProof != None
    
    # Verify disclosure proof
    ret_code = c.verify_disclosure_proof(pk, disProof, hid_att)
    assert ret_code 

    
def test_verify_disclosure_proof_bigNumbers():
    subscription_map = {}
    subscription_map['a'] = (1, c.Bn(100123))
    subscription_map['b'] = (2, c.Bn(201234))
    subscription_map['c'] = (3, c.Bn(10321))
    subscription_map['d'] = (4, c.Bn(31273))

    attributes = list(subscription_map.values())

    (sk,pk) = c.generate_key(attributes)
    
    ua_str = ['d', 'a']
    ua = [subscription_map[c] for c in ua_str]

    ia_str = ['b', 'c']
    ia = [subscription_map[c] for c in ia_str]
    
    (request, t) = c.create_issue_request(pk, ua)
    response = c.sign_issue_request(sk, pk, request, ia_str, subscription_map)
    anon_cred = c.obtain_credential(pk, response, t, attributes)
    assert anon_cred != None
    
    hid_att_str = ['d', 'a', 'c']
    hid_att = [subscription_map[e] for e in hid_att_str]

    # Create disclosure proof
    disProof = c.create_disclosure_proof(pk, anon_cred, hid_att)
    assert disProof != None
    
    # Verify disclosure proof
    ret_code = c.verify_disclosure_proof(pk, disProof, hid_att)
    assert ret_code 