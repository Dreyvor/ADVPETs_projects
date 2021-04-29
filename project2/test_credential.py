#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Thu Apr 29 14:05:21 2021

@author: benoit
"""

import credential as c
import numpy as np
    
def test_id():
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
    
    sp = c.G1.generator() ** c.G1.order().random()
    while(s == sp):
        sp = c.G1.generator() ** c.G1.order.random()
    
    res = c.verify(pk,(h,sp),msgs)

    assert not res