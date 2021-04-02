#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Integration tests that verify different aspects of the protocol.
You can *add* new tests here, but it is best to  add them to a new test file.

ALL EXISTING TESTS IN THIS SUITE SHOULD PASS WITHOUT ANY MODIFICATION TO THEM.
"""

import time
from multiprocessing import Process, Queue

import pytest

from expression import Scalar, Secret
from protocol import ProtocolSpec
from server import run

from smc_party import SMCParty
import csv
import numpy as np

from secret_sharing import q
import sys #increase depth recursion limit

def smc_client(client_id, prot, value_dict, queue):
    cli = SMCParty(
        client_id,
        "localhost",
        5000,
        protocol_spec=prot,
        value_dict=value_dict
    )
    res = cli.run()
    queue.put(res)
    print(f"{client_id} has finished!")
    
    file = open('output_bench_bytes.csv','a')
    print_bytes = str(cli.comm.bytes_total) + ","
    print(print_bytes, file=file, end='')
    file.close()


def smc_server(args):
    run("localhost", 5000, args)


def run_processes(server_args, *client_args):
    queue = Queue()

    server = Process(target=smc_server, args=(server_args,))
    clients = [Process(target=smc_client, args=(*args, queue)) for args in client_args]

    server.start()
    time.sleep(3)
    for client in clients:
        client.start()

    results = list()
    for client in clients:
        client.join()

    for client in clients:
        results.append(queue.get())

    server.terminate()
    server.join()

    # To "ensure" the workers are dead.
    time.sleep(2)

    print("Server stopped.")

    return results


def suite(parties, expr, expected):
    participants = list(parties.keys())

    prot = ProtocolSpec(expr=expr, participant_ids=participants)
    clients = [(name, prot, value_dict) for name, value_dict in parties.items()]

    results = run_processes(participants, *clients)

    print("expected:\t", expected)
    print("results:\t", results)
    for result in results:
        assert result == expected

    
def str_n_addition_secrets(n:int): 
    nb_launch = 15
    for i in range(nb_launch):

        t_start_i = time.time()
        
        parties = {}            
        for j in range(5): #with always 5 participants
            act_secret = Secret()
            parties[str(j)] = {act_secret: 10} #fixed secret value 

        expr = Scalar(0)           
        for j in range(n): #number of additions
            if(j == 0):
                expr = list(parties[str(0)].keys())[0]
            else:
                expr = expr + list(parties[str(j % 5)].keys())[0]
        
        expected = n*10 % q
        suite(parties,expr,expected)
        
        t_total_i = time.time() - t_start_i
        file = open('output_bench_sec_add','a')
        print_time = str(t_total_i)
        print(print_time, file=file)
        file.close()
        
def str_n_addition_scalars(n:int): 
    nb_launch = 15
    for i in range(nb_launch):

        t_start_i = time.time()
        
        parties = {}            
        for j in range(5): #with always 5 participants
            act_secret = Secret()
            parties[str(j)] = {act_secret: 10} #fixed secret value 

        expr = Scalar(10)         
        for j in range(1,n): #number of additions
            expr = expr + Scalar(10)
            
        print(expr)
        expected = n*10 % q
        suite(parties,expr,expected)
        
        t_total_i = time.time() - t_start_i
        file = open('output_bench_scal_add','a')
        print_time = str(t_total_i)
        print(print_time, file=file)
        file.close()
        
def str_n_mult_secrets(n:int): 
    nb_launch = 15
    for i in range(nb_launch):

        t_start_i = time.time()
        
        parties = {}            
        for j in range(5): #with always 5 participants
            act_secret = Secret()
            parties[str(j)] = {act_secret: 3} #fixed secret value 

        expr = Scalar(1)           
        for j in range(n): #number of additions
            if(j == 0):
                expr = list(parties[str(0)].keys())[0]
            else:
                expr = expr * list(parties[str(j % 5)].keys())[0]
        
        print(expr)
        expected = 3**n % q
        suite(parties,expr,expected)
        
        t_total_i = time.time() - t_start_i
        file = open('output_bench_sec_mul','a')
        print_time = str(t_total_i)
        print(print_time, file=file)
        file.close()
        
def str_n_mult_scalars(n:int): 
    nb_launch = 15
    for i in range(nb_launch):

        t_start_i = time.time()
        
        parties = {}            
        for j in range(5): #with always 5 participants
            act_secret = Secret()
            parties[str(j)] = {act_secret: 3} #fixed secret value 

        expr = Scalar(3)           
        for j in range(1,n): #number of additions
            expr = expr * Scalar(3)
        
        print(expr)
        expected = 3**n % q
        suite(parties,expr,expected)
        
        t_total_i = time.time() - t_start_i
        file = open('output_bench_scal_mul','a')
        print_time = str(t_total_i)
        print(print_time, file=file)
        file.close()
        
        
def str_nb_participants(n:int): 
    
    
    #simple circuit : f(a,b,...) = K + a + b + ...
    nb_launch = 15
    for i in range(nb_launch):

        t_start_i = time.time()
        
        parties = {}
        expr = Scalar(5)
        for j in range(n): #with n participants
            act_secret = Secret()
            parties[str(j)] = {act_secret: 3} #fixed secret value 
            expr = expr + act_secret

        print(expr)
        expected = (5 + 3*n) % q
        suite(parties,expr,expected)
        
        t_total_i = time.time() - t_start_i
        file = open('output_bench_nb_part','a')
        print_time = str(t_total_i)
        print(print_time, file=file)
        file.close()
        
    
def test_bench():
    
    sys.setrecursionlimit(10000)
    
    t_start = time.time()
    
    str_n_addition_scalars(100)
    
    t_total = round((time.time()-t_start)*1000) #time in ms
    
    results = []
    with open("output_bench_bytes.csv") as csvfile:
        reader = csv.reader(csvfile, quoting=csv.QUOTE_NONNUMERIC)
        for row in reader: # each row is a list
            results.append(row)
  
    np_results = (np.array(results)).flatten()
    np_results = np_results[:-1] #remove last element which is ""
    np_results = np_results.astype(np.float)
    nb_bytes = np.sum(np_results)
    
    file = open('output_bench','a')
    print_time = "TOTAL COMPUTATION TIME [ms]: " + str(t_total)
    print_bytes = "TOTAL BYTES : " + str(nb_bytes)
    print(print_time, file=file)
    print(print_bytes, file=file)
    file.close()
    

def tests():
    test_bench()
    

tests()