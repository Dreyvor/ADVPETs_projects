#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Thu Apr 29 14:05:21 2021

@author: benoit
"""

import credential as c
import numpy as np

from petrelic.multiplicative.pairing import G1, G2, GT
from petrelic.bn import Bn

import string



nb_msgs = 30
np.random.seed(None)

############################
# TEST GENKEY, SIG, VERIFY #
############################
def test_gen_sign_verify():
    msgs = [(i+1, G1.order().random()) for i in range(nb_msgs)]

    (sk, pk) = c.generate_key(msgs)
    (x, X, y) = sk
    (g, Y, gt, Xt, Yt) = pk

    assert len(y) == len(Y) == len(Yt) == nb_msgs
    assert X == g**x
    assert Xt == gt**x

    for i, y in enumerate(y):
        assert(Y[i][0] == y[0] and Y[i][1] == g**y[1])
        assert(Yt[i][0] == y[0] and Yt[i][1] == gt**y[1])

    sig: c.Signature = c.sign(sk, msgs)
    assert sig != None

    assert c.verify(pk, sig, msgs)

def test_verify_neutral():
    msgs = [(i+1, G1.order().random()) for i in range(nb_msgs)]
    
    (sk,pk) = c.generate_key(msgs)
    sig = c.sign(sk, msgs)
    assert sig != None
    (h, s) = sig

    assert not c.verify(pk, (c.G1.neutral_element, s), msgs)

def test_verify_wrong_msg():
    msgs = [(i+1, G1.order().random()) for i in range(nb_msgs)]

    (sk,pk) = c.generate_key(msgs)    
    sig = c.sign(sk,msgs)
    assert sig != None
    (h,s) = sig

    idx = np.random.choice(len(msgs))

    msgs[idx] = (idx+1, G1.order().random())
    assert not c.verify(pk, sig, msgs)
    
def test_verify_wrong_sig():
    msgs = [(i+1, G1.order().random()) for i in range(nb_msgs)]
    
    (sk, pk) = c.generate_key(msgs)
    
    sig = c.sign(sk, msgs)
    assert sig != None
    (h, s) = sig
    
    sp = c.G1.generator() ** c.G1.order().random()
    while(sp.eq(s)):
        sp = c.G1.generator() ** c.G1.order().random()
    
    assert not c.verify(pk, (h, sp), msgs)


##########################
# TEST ISSUANCE PROTOCOL #
##########################
def test_request():
    msgs = [(i+1, G1.order().random()) for i in range(nb_msgs)]
    
    (sk, pk) = c.generate_key(msgs)
    
    ua_idx = np.random.choice(nb_msgs, np.random.randint(1, np.ceil(.4 * nb_msgs)), replace=False)

    ua = [(idx+1, msgs[idx][1]) for idx in ua_idx]
    
    ((challenge, zkp), t) = c.create_issue_request(pk, ua)

    assert challenge != None and zkp != None and t != None


def test_sign_request():
    msgs = [(i+1, G1.order().random()) for i in range(nb_msgs)]
    key_str = [''.join(np.random.choice(list(string.ascii_letters + string.digits), 10)) for _ in range(nb_msgs)]

    msgs_dict = {k: v for k,v in zip(key_str, msgs)}
    
    (sk, pk) = c.generate_key(msgs_dict.values())
    
    ua_keys = np.random.choice(key_str, np.random.randint(1, np.ceil(.4 * nb_msgs)), replace=False)
    ua = [v for k,v in msgs_dict.items() if k in ua_keys]

    ia_keys = [k for k in key_str if k not in ua_keys]
    ia = [v for k, v in msgs_dict.items() if k in ia_keys]

    (request, t) = c.create_issue_request(pk, ua)
    (sig1, sig2) = c.sign_issue_request(sk, pk, request, ia_keys, msgs_dict)

    assert sig1 != None and sig2 != None

def test_sign_request_wrong_zkp():
    msgs = [(i+1, G1.order().random()) for i in range(nb_msgs)]
    key_str = [''.join(np.random.choice(list(string.ascii_letters + string.digits), 10)) for _ in range(nb_msgs)]

    msgs_dict = {k: v for k,v in zip(key_str, msgs)}
    
    (sk, pk) = c.generate_key(msgs_dict.values())
    
    ua_keys = np.random.choice(key_str, np.random.randint(1, np.ceil(.4 * nb_msgs)), replace=False)
    ua = [v for k,v in msgs_dict.items() if k in ua_keys]

    ia_keys = [k for k in key_str if k not in ua_keys]
    ia = [v for k, v in msgs_dict.items() if k in ia_keys]

    wrong_choice_keys = np.random.choice(key_str, np.random.randint(1, nb_msgs), replace=False)
    while wrong_choice_keys is ua_keys:
        wrong_choice_keys = np.random.choice(key_str, np.random.randint(1, nb_msgs), replace=False)

    wrong_choice = [v for k, v in msgs_dict.items() if k in wrong_choice_keys]
    
    issue_req_1 = c.create_issue_request(pk, ua)
    assert issue_req_1 != None
    ((commitment, zkp), t) = issue_req_1

    zkp2 = c.generate_zkp_prover_side(pk, t, wrong_choice, commitment)
    
    request = (commitment, zkp2)
    res = c.sign_issue_request(sk, pk, request, ia_keys, msgs_dict)

    assert res == None

def test_obtain_cred_wrong_sig():
    msgs = [(i+1, G1.order().random()) for i in range(nb_msgs)]
    key_str = [''.join(np.random.choice(list(string.ascii_letters + string.digits), 10)) for _ in range(nb_msgs)]

    msgs_dict = {k: v for k,v in zip(key_str, msgs)}
    
    (sk, pk) = c.generate_key(msgs_dict.values())
    
    ua_keys = np.random.choice(key_str, np.random.randint(1, np.ceil(.4 * nb_msgs)), replace=False)
    ua = [v for k,v in msgs_dict.items() if k in ua_keys]

    ia_keys = [k for k in key_str if k not in ua_keys]
    ia = [v for k, v in msgs_dict.items() if k in ia_keys]
    
    issue_req_1 = c.create_issue_request(pk, ua)
    assert issue_req_1 != None
    (request, t) = issue_req_1

    (sig1, sig2) = c.sign_issue_request(sk, pk, request, ia_keys, msgs_dict)
    
    sig1_n = c.G1.generator() ** c.G1.order().random()
    while(sig1_n.eq(sig1)):
        sig1_n = c.G1.generator() ** c.G1.order().random()
    
    res = c.obtain_credential(pk, (sig1_n, sig2), t, msgs)
    
    assert res == None


def test_obtain_cred():
    subscription_atts = [(i+1, G1.order().random()) for i in range(nb_msgs)]
    subscription_keys = [''.join(np.random.choice(list(string.ascii_letters + string.digits), 10)) for _ in range(nb_msgs)]

    subscription_map = {k: v for k,v in zip(subscription_keys, subscription_atts)}
    
    (sk, pk) = c.generate_key(subscription_map.values())
    
    ua_keys = np.random.choice(subscription_keys, np.random.randint(1, np.ceil(.4 * nb_msgs)), replace=False)
    ua = [v for k,v in subscription_map.items() if k in ua_keys]

    ia_keys = [k for k in subscription_keys if k not in ua_keys]
    ia = [v for k, v in subscription_map.items() if k in ia_keys]
    
    issue_req_1 = c.create_issue_request(pk, ua)
    assert(issue_req_1 != None)
    (request, t) = issue_req_1

    response = c.sign_issue_request(sk, pk, request, ia_keys, subscription_map)
    assert(response != None)
       
    anon_cred = c.obtain_credential(pk, response, t, subscription_atts)
    
    assert anon_cred != None
    

#########################
# TEST SHOWING PROTOCOL #
#########################

def test_create_verify_disclosure_proof():
    subscription_atts = [(i+1, G1.order().random()) for i in range(nb_msgs)]
    subscription_keys = [''.join(np.random.choice(list(string.ascii_letters + string.digits), 10)) for _ in range(nb_msgs)]

    subscription_map = {k: v for k,v in zip(subscription_keys, subscription_atts)}
    
    (sk, pk) = c.generate_key(subscription_map.values())
    
    ua_keys = np.random.choice(subscription_keys, np.random.randint(1, np.ceil(.4 * nb_msgs)), replace=False)
    ua = [v for k,v in subscription_map.items() if k in ua_keys]

    ia_keys = [k for k in subscription_keys if k not in ua_keys]
    ia = [v for k, v in subscription_map.items() if k in ia_keys]
    
    (request, t) = c.create_issue_request(pk, ua)

    response = c.sign_issue_request(sk, pk, request, ia_keys, subscription_map)
       
    anon_cred = c.obtain_credential(pk, response, t, subscription_atts)
    assert anon_cred != None
    
    # Testing disclosure proof
    hid_att_keys = np.random.choice(subscription_keys, np.random.randint(1, np.ceil(.4 * nb_msgs)), replace=False)
    hid_att = [subscription_map[e] for e in hid_att_keys]

    # Create disclosure proof
    disProof = c.create_disclosure_proof(pk, anon_cred, hid_att)
    assert( len(disProof[1]) == nb_msgs - len(hid_att_keys))

    hid_att_idx = [i for i, _ in hid_att]
    for disc_key in  [i for i, _ in disProof[1]]:
        assert disc_key not in hid_att_idx

    # Verify disclosure proof
    assert c.verify_disclosure_proof(pk, disProof)