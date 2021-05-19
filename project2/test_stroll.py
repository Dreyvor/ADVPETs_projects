from serialization import jsonpickle
from stroll import Server, Client


def test_full_stroll_run():

    subscriptions = ['appartment_block', 'bar', 'cafeteria']

    #### SERVER SIDE
    pair = Server.generate_ca(subscriptions)
    server_sk = pair[0]
    server_pk = pair[1]

    SERVER = Server()

    #### CLIENT SIDE

    CLIENT = Client()
    username = "test_client"

    client_subs = ['bar', 'cafeteria']
    issue_request, state = CLIENT.prepare_registration(server_pk, username, client_subs)

    #### SERVER SIDE

    processed_registration = SERVER.process_registration(server_sk, server_pk, issue_request, username, client_subs)
    
    #### CLIENT SIDE

    credentials = CLIENT.process_registration_response(server_pk, processed_registration, state)
    
    lat = 46.50448649
    lon = 6.55963052
    message = (f"{lat},{lon}").encode("utf-8")
    types = ['bar']

    request = CLIENT.sign_request(server_pk, credentials, message, types)

    #### SERVER SIDE

    assert SERVER.check_request_signature(server_pk, message, types, request)

'''
def test_stroll_wrong_sub():

    subscriptions = ['appartment_block', 'bar', 'cafeteria']

    #### SERVER SIDE
    pair = Server.generate_ca(subscriptions)
    server_sk = pair[0]
    server_pk = pair[1]

    SERVER = Server()

    #### CLIENT SIDE

    CLIENT = Client()
    username = "test_client"

    client_subs = ['bar', 'cafeteria']
    issue_request, state = CLIENT.prepare_registration(server_pk, username, client_subs)

    #### SERVER SIDE

    processed_registration = SERVER.process_registration(server_sk, server_pk, issue_request, username, client_subs)

    #### CLIENT SIDE

    credentials = CLIENT.process_registration_response(server_pk, processed_registration, state)
    
    lat = 46.50448649
    lon = 6.55963052
    message = (f"{lat},{lon}").encode("utf-8")
    types = ['restaurant']

    request = CLIENT.sign_request(server_pk, credentials, message, types)

    #### SERVER SIDE

    assert not SERVER.check_request_signature(server_pk, message, types, request)


def test_stroll_connect_with_stolen_disclosure_proof():

    subscriptions = ['appartment_block', 'bar', 'cafeteria']

    #### SERVER SIDE
    pair = Server.generate_ca(subscriptions)
    server_sk = pair[0]
    server_pk = pair[1]

    SERVER = Server()

    #### CLIENT SIDE

    CLIENT = Client()
    username = "test_client"

    client_subs = ['bar', 'cafeteria']
    issue_request, state = CLIENT.prepare_registration(server_pk, username, client_subs)

    BAD_CLIENT = Client()
    username2 = "bad_client"


    issue_request2, state2 = BAD_CLIENT.prepare_registration(server_pk, username2, client_subs)

    #### SERVER SIDE

    processed_registration = SERVER.process_registration(server_sk, server_pk, issue_request, username, client_subs)
    processed_registration2 = SERVER.process_registration(server_sk, server_pk, issue_request2, username2, client_subs)

    #### CLIENT SIDE

    credentials = CLIENT.process_registration_response(server_pk, processed_registration, state)
    credentials2 = BAD_CLIENT.process_registration_response(server_pk, processed_registration2, state2)
    
    lat = 46.50448649
    lon = 6.55963052
    message = (f"{lat},{lon}").encode("utf-8")
    types = ['bar']

    request = CLIENT.sign_request(server_pk, credentials, message, types)

    #### BAD CLIENT stole disclosure proof and try to request with it
    request2 = BAD_CLIENT.sign_request(server_pk, credentials2, message, types)

    bls_sign2, _ = jsonpickle.decode(request2)
    _, proof = jsonpickle.decode(request)

    request_forged = jsonpickle.encode((bls_sign2, proof)).encode()

    #### SERVER SIDE

    assert not SERVER.check_request_signature(server_pk, message, types, request_forged)'''