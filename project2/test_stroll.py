from serialization import jsonpickle
from stroll import Server, Client

#all_subscriptions = ['appartment_block', 'bar', 'cafeteria', 'club', 'company', 'dojo', 'gym', 'laboratory', 'office',
#                     'restaurant', 'supermarket', 'villa']

def test_run():

    subscriptions = ['appartment_block', 'bar','cafeteria']

    SERVER = Server()
    (s_sk, s_pk) = Server.generate_ca(subscriptions)
    
    CLIENT = Client()
    c_subs = ['bar']
    username = 'client1'
    
    (issue_request, state) = CLIENT.prepare_registration(s_pk, username, c_subs)

    registration = SERVER.process_registration(s_sk, s_pk, issue_request, username, c_subs)
    
    credentials = CLIENT.process_registration_response(s_pk, registration, state)
    
    message = "46.52345,6.57890".encode('utf-8')
    types = ['bar']
    request = CLIENT.sign_request(s_pk, credentials, message, types)

    assert SERVER.check_request_signature(s_pk, message, types, request)


def test_sub_not_valid():

    subscriptions = ['appartment_block', 'bar']

    SERVER = Server()
    (s_sk, s_pk) = Server.generate_ca(subscriptions)

    CLIENT = Client()
    c_subs = ['bar']
    username = 'client1'
    
    (issue_request, state) = CLIENT.prepare_registration(s_pk, username, c_subs)

    processed_registration = SERVER.process_registration(s_sk, s_pk, issue_request, username, c_subs)

    credentials = CLIENT.process_registration_response(s_pk, processed_registration, state)
    
    message = "46.52345,6.57890".encode('utf-8')
    types = ['cafeteria'] # not a valid subscription

    request = CLIENT.sign_request(s_pk, credentials, message, types)

    assert not SERVER.check_request_signature(s_pk, message, types, request)


def test_wrong_disclosure_proof():

    subscriptions = ['appartment_block', 'bar']

    SERVER = Server()
    (s_sk, s_pk) = Server.generate_ca(subscriptions)
    
    CLIENT1 = Client()
    c1_subs = ['bar']
    username1 = 'client1'

    CLIENT2 = Client()
    c2_subs = ['appartment_block']
    username2 = 'client2'
    
    (issue_request1, state1) = CLIENT1.prepare_registration(s_pk, username1, c1_subs)
    (issue_request2, state2) = CLIENT2.prepare_registration(s_pk, username2, c2_subs)

    registration1 = SERVER.process_registration(s_sk, s_pk, issue_request1, username1, c1_subs)
    registration2 = SERVER.process_registration(s_sk, s_pk, issue_request2, username2, c2_subs)

    credentials1 = CLIENT1.process_registration_response(s_pk, registration1, state1)
    credentials2 = CLIENT2.process_registration_response(s_pk, registration2, state2)
        
    message = "46.52345,6.57890".encode('utf-8')
    types1 = ['bar']
    types2 = ['appartment_block']
    
    request1 = CLIENT2.sign_request(s_pk, credentials1, message, types1)
    request2 = CLIENT2.sign_request(s_pk, credentials2, message, types2)

    (c1_sig, c1_pk, c1_proof) = jsonpickle.decode(request1)
    (c2_sig, c2_pk, c2_proof) = jsonpickle.decode(request2)
    
    # Client 2 uses the disclosure proof of client 1
    request3 = jsonpickle.encode((c2_sig, c2_pk, c1_proof))

    assert not SERVER.check_request_signature(s_pk, message, types2, request3)
