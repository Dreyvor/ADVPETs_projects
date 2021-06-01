from serialization import jsonpickle
from stroll import Server, Client

#all_subscriptions = ['appartment_block', 'bar', 'cafeteria', 'club', 'company', 'dojo', 'gym', 'laboratory', 'office',
#                     'restaurant', 'supermarket', 'villa']

def test_run():

    subscriptions = ['appartment_block', 'bar','cafeteria']

    SERVER = Server()
    (s_sk, s_pk) = Server.generate_ca(subscriptions)
    
    c_subs = ['bar', 'cafeteria']
    username = 'client1'
    CLIENT = Client(username, c_subs)

    (issue_request, state) = CLIENT.prepare_registration(s_pk, username, CLIENT.subs_list)
    assert jsonpickle.decode(issue_request) != None

    registration = SERVER.process_registration(s_sk, s_pk, issue_request, CLIENT.username, CLIENT.subs_list)
    assert jsonpickle.decode(registration) != None
    
    credentials = CLIENT.process_registration_response(s_pk, registration, state)
    assert jsonpickle.decode(credentials) != None
        
    message = "46.52345,6.57890".encode('utf-8')
    types = ['bar']
    signature = CLIENT.sign_request(s_pk, credentials, message, types)
    assert jsonpickle.decode(signature) != None

    assert SERVER.check_request_signature(s_pk, message, types, signature)


def test_sub_not_valid():

    subscriptions = ['appartment_block', 'bar']

    SERVER = Server()
    (s_sk, s_pk) = Server.generate_ca(subscriptions)

    c_subs = ['bar']
    username = 'client1'
    CLIENT = Client(username, c_subs)
    
    (issue_request, state) = CLIENT.prepare_registration(s_pk, CLIENT.username, CLIENT.subs_list)

    processed_registration = SERVER.process_registration(s_sk, s_pk, issue_request, CLIENT.username, CLIENT.subs_list)

    credentials = CLIENT.process_registration_response(s_pk, processed_registration, state)
    
    message = "46.52345,6.57890".encode('utf-8')
    types = ['cafeteria'] # not a valid subscription

    request = CLIENT.sign_request(s_pk, credentials, message, types)

    assert not SERVER.check_request_signature(s_pk, message, types, request)

def test_not_sub_type_request():

    subscriptions = ['appartment_block', 'bar']

    SERVER = Server()
    (s_sk, s_pk) = Server.generate_ca(subscriptions)

    c_subs = ['bar']
    username = 'client1'
    CLIENT = Client(username, c_subs)
    
    (issue_request, state) = CLIENT.prepare_registration(s_pk, CLIENT.username, CLIENT.subs_list)

    processed_registration = SERVER.process_registration(s_sk, s_pk, issue_request, CLIENT.username, CLIENT.subs_list)

    credentials = CLIENT.process_registration_response(s_pk, processed_registration, state)
    
    message = "46.52345,6.57890".encode('utf-8')
    types = ['appartment_block'] # not a valid type requested

    request = CLIENT.sign_request(s_pk, credentials, message, types)

    assert not SERVER.check_request_signature(s_pk, message, types, request)


def test_wrong_disclosure_proof():

    subscriptions = ['appartment_block', 'bar']

    SERVER = Server()
    (s_sk, s_pk) = Server.generate_ca(subscriptions)
    
    c1_subs = ['bar']
    username1 = 'client1'
    CLIENT1 = Client(username1, c1_subs)

    # c2_subs = ['appartment_block']
    c2_subs = ['bar']
    username2 = 'client2'
    CLIENT2 = Client(username2, c2_subs)
    
    (issue_request1, state1) = CLIENT1.prepare_registration(s_pk, CLIENT1.username, CLIENT1.subs_list)
    (issue_request2, state2) = CLIENT2.prepare_registration(s_pk, CLIENT2.username, CLIENT2.subs_list)

    registration1 = SERVER.process_registration(s_sk, s_pk, issue_request1, CLIENT1.username, CLIENT1.subs_list)
    registration2 = SERVER.process_registration(s_sk, s_pk, issue_request2, CLIENT2.username, CLIENT2.subs_list)

    credentials1 = CLIENT1.process_registration_response(s_pk, registration1, state1)
    credentials2 = CLIENT2.process_registration_response(s_pk, registration2, state2)
        
    message = "46.52345,6.57890".encode('utf-8')
    types1 = ['bar']
    # types2 = ['appartment_block']
    types2 = ['bar']
    
    request1 = CLIENT2.sign_request(s_pk, credentials1, message, types1)
    request2 = CLIENT2.sign_request(s_pk, credentials2, message, types2)

    (c1_sig, c1_proof) = jsonpickle.decode(request1)
    (c2_sig, c2_proof) = jsonpickle.decode(request2)
    
    # Client 2 uses the disclosure proof of client 1
    request3 = jsonpickle.encode((c2_sig, c1_proof)).encode()

    assert not SERVER.check_request_signature(s_pk, message, types2, request3)
