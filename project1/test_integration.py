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


def test_suite1():
    """
    f(a, b, c) = a + b + c
    """
    print('start test suite 1')
    alice_secret = Secret()
    bob_secret = Secret()
    charlie_secret = Secret()

    parties = {
        "Alice": {alice_secret: 3},
        "Bob": {bob_secret: 14},
        "Charlie": {charlie_secret: 2}
    }

    expr = (alice_secret + bob_secret + charlie_secret)
    expected = 3 + 14 + 2
    suite(parties, expr, expected)



def test_suite2():
    """
    f(a, b) = a - b
    """
    alice_secret = Secret()
    bob_secret = Secret()

    parties = {
        "Alice": {alice_secret: 14},
        "Bob": {bob_secret: 3},
    }

    expr = (alice_secret - bob_secret)
    expected = 14 - 3
    suite(parties, expr, expected)


def test_suite3():
    """
    f(a, b, c) = (a + b + c) ∗ K
    """
    alice_secret = Secret()
    bob_secret = Secret()
    charlie_secret = Secret()

    parties = {
        "Alice": {alice_secret: 3},
        "Bob": {bob_secret: 14},
        "Charlie": {charlie_secret: 2}
    }

    expr = ((alice_secret + bob_secret + charlie_secret) * Scalar(5))
    expected = (3 + 14 + 2) * 5
    suite(parties, expr, expected)


def test_suite4():
    """
    f(a, b, c) = (a + b + c) + K
    """
    alice_secret = Secret()
    bob_secret = Secret()
    charlie_secret = Secret()

    parties = {
        "Alice": {alice_secret: 3},
        "Bob": {bob_secret: 14},
        "Charlie": {charlie_secret: 2}
    }

    expr = ((alice_secret + bob_secret + charlie_secret) + Scalar(5))
    expected = (3 + 14 + 2) + 5
    suite(parties, expr, expected)


def test_suite5():
    """
    f(a, b, c) = (a ∗ K0 + b - c) + K1
    """
    alice_secret = Secret()
    bob_secret = Secret()
    charlie_secret = Secret()

    parties = {
        "Alice": {alice_secret: 3},
        "Bob": {bob_secret: 14},
        "Charlie": {charlie_secret: 2}
    }

    expr = (((alice_secret * Scalar(5)) + bob_secret - charlie_secret) + Scalar(9))
    expected = ((3 * 5) + 14 - 2) + 9
    suite(parties, expr, expected)


def test_suite6():
    """
    f(a, b, c, d) = a + b + c + d
    """
    alice_secret = Secret()
    bob_secret = Secret()
    charlie_secret = Secret()
    david_secret = Secret()

    parties = {
        "Alice": {alice_secret: 3},
        "Bob": {bob_secret: 14},
        "Charlie": {charlie_secret: 2},
        "David": {david_secret: 5}
    }

    expr = (alice_secret + bob_secret + charlie_secret + david_secret)
    expected = 3 + 14 + 2 + 5
    suite(parties, expr, expected)


def test_suite7():
    """
    f(a, b, c) = (a ∗ b) + (b ∗ c) + (c ∗ a)
    """
    alice_secret = Secret()
    bob_secret = Secret()
    charlie_secret = Secret()

    parties = {
        "Alice": {alice_secret: 3},
        "Bob": {bob_secret: 14},
        "Charlie": {charlie_secret: 2}
    }

    expr = (
        (alice_secret * bob_secret) +
        (bob_secret * charlie_secret) +
        (charlie_secret * alice_secret)
    )
    expected = ((3 * 14) + (14 * 2) + (2 * 3))
    suite(parties, expr, expected)


def test_suite8():
    """
    f(a, b, c, d, e) = ((a + K0) + b ∗ K1 - c) ∗ (d + e)
    """
    alice_secret = Secret()
    bob_secret = Secret()
    charlie_secret = Secret()
    david_secret = Secret()
    elusinia_secret = Secret()

    parties = {
        "Alice": {alice_secret: 3},
        "Bob": {bob_secret: 14},
        "Charlie": {charlie_secret: 2},
        "David": {david_secret: 5},
        "Elusinia": {elusinia_secret: 7}
    }

    expr = (
        (
            (alice_secret + Scalar(8)) +
            ((bob_secret * Scalar(9)) - charlie_secret)
         ) * (david_secret + elusinia_secret)
    )
    expected = (((3 + 8) + (14 * 9) - 2) * (5 + 7))
    suite(parties, expr, expected)

def test_suite9():
    """
    f(a, b, c) = (a ∗ b) + (b ∗ c) + (c ∗ a)
    """
    alice_secret = Secret()
    bob_secret = Secret()

    parties = {
        "Alice": {alice_secret: 3},
        "Bob": {bob_secret: 14},
    }

    expr = (
        (alice_secret * bob_secret)
    )
    expected = 3 * 14
    suite(parties, expr, expected)
    
def test_application():
    """
    3 families of friends want to go together for 3 different trips during the vacations.
    Each has to put a certain (secret) amount of money on the shared electronic wallet.
    Also each family has to vote (secretly) wether or not they agree to take the plane to destinations.
    """
    
    # Manage money
    f1_money_trip_1 = Secret()
    f1_money_trip_2_3 = Secret()
    f2_money_trip_1_2 = Secret()
    f2_money_trip_3 = Secret()
    f3_money_trip_1_2_3 = Secret()
    parties_money = {
            "F1_money": {f1_money_trip_1: 1000, f1_money_trip_2_3: 800},
            "F2_money": {f2_money_trip_1_2: 2000, f2_money_trip_3: 1300},
            "F3_money": {f3_money_trip_1_2_3: 10000},
            }
    expr1 = (f1_money_trip_1 + Scalar(2) * f1_money_trip_2_3) \
            + (Scalar(2) * f2_money_trip_1_2 + f2_money_trip_3) \
            + (Scalar(3) * f3_money_trip_1_2_3)
    expected_money = (1000 + 2*800) + (2*2000 + 1300) + (3*10000)
    suite(parties_money, expr1, expected_money)
    
    # Manage plane votes
    f1_plane = Secret()
    f2_plane= Secret()
    f3_plane= Secret()
    parties_plane = {
            "F1_plane": {f1_plane: 1},
            "F2_plane": {f2_plane: 1},
            "F3_plane": {f3_plane: 0}, # Family 3 does not agree
            }
    expr2 = f1_plane * f2_plane * f3_plane
    expected_plane = 1*1*0
    suite(parties_plane, expr2, expected_plane)