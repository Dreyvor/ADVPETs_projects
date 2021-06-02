from serialization import jsonpickle
from stroll import Server, Client

import numpy as np

import time as t
from tqdm import tqdm


all_subscriptions = ['appartment_block', 'bar', 'cafeteria',
                    'club', 'company', 'dojo', 'gym', 'laboratory',
                    'office', 'restaurant', 'supermarket', 'villa']

NB_RUN_FINE = int(1e4)
NB_RUN_COARSE = int(1e1)

def eval_multiple_run(fct, nb_run, name=None):
    gen_key_times = np.array([])
    register_times = np.array([])
    show_creds_times = np.array([])
    verify_sign_times = np.array([])
    global_times = np.array([])

    print("#"*60)
    print("" if name is None else name.upper(), end=' ')
    print("with {} runs".format(nb_run))
    for i in tqdm(range(nb_run)):
        global_start = t.time()
        gen_key_time, register_time, show_creds_time, verify_sign_time = fct()
        global_times = np.append(global_times, t.time() - global_start)

        gen_key_times = np.append(gen_key_times, gen_key_time)
        register_times = np.append(register_times, register_time)
        show_creds_times = np.append(show_creds_times, show_creds_time)
        verify_sign_times = np.append(verify_sign_times, verify_sign_time)

    # Prints timings
    print("--- GEN_KEYS:\t\t\t mean {:.5f} ms ; std {:.5f} ms ---".format(np.mean(gen_key_times)*1e3, np.std(gen_key_times)*1e3))
    print("--- ISSUANCE:\t\t\t mean {:.5f} ms ; std {:.5f} ms ---".format(np.mean(register_times)*1e3, np.std(register_times)*1e3))
    print("--- SHOW_CREDS:\t\t\t mean {:.5f} ms ; std {:.5f} ms ---".format(np.mean(show_creds_times)*1e3, np.std(show_creds_times)*1e3))
    print("--- VERIFY_SIGNED_REQUEST:\t mean {:.5f} ms ; std {:.5f} ms ---".format(np.mean(verify_sign_times)*1e3, np.std(verify_sign_times)*1e3))
    print("--- GLOBAL:\t\t\t mean {:.5f} ms ; std {:.5f} ms ---".format(np.mean(global_times)*1e3, np.std(global_times)*1e3))


def eval_stroll_full_random():
    subscriptions = np.random.choice(all_subscriptions, np.random.randint(1, len(all_subscriptions)+1), replace=False)

    SERVER = Server()
    s_time = t.time()
    (s_sk, s_pk) = Server.generate_ca(subscriptions)
    gen_key_time = t.time() - s_time
    
    c_subs = np.random.choice(subscriptions, np.random.randint(1, len(subscriptions)+1), replace=False)
    username = 'client_1'
    CLIENT = Client(username, c_subs)

    s_time = t.time()
    (issue_request, state) = CLIENT.prepare_registration(s_pk, username, CLIENT.subs_list)
    # assert jsonpickle.decode(issue_request) != None

    registration = SERVER.process_registration(s_sk, s_pk, issue_request, CLIENT.username, CLIENT.subs_list)
    # assert jsonpickle.decode(registration) != None
    
    credentials = CLIENT.process_registration_response(s_pk, registration, state)
    # assert jsonpickle.decode(credentials) != None
    register_time = t.time() - s_time
        
    first_coord = np.random.uniform(46.5, 46.57) 
    second_coord = np.random.uniform(6.55, 6.65)
    message = (str(first_coord) + "," + str(second_coord)).encode('utf-8')
    types = np.random.choice(c_subs, np.random.randint(1, len(c_subs)+1), replace=False)
    s_time = t.time()        
    signature = CLIENT.sign_request(s_pk, credentials, message, types)
    # assert jsonpickle.decode(signature) != None
    show_creds_time = t.time() - s_time

    s_time = t.time()        
    result = SERVER.check_request_signature(s_pk, message, types, signature)
    # assert result
    verify_sign_time = t.time() - s_time

    return gen_key_time, register_time, show_creds_time, verify_sign_time

def eval_stroll_global_time(nb_run, nb_clients, nb_reqs):
    gen_key_times = np.zeros(nb_run)
    register_times = np.zeros((nb_run, nb_clients))
    show_creds_times = np.zeros((nb_run, nb_clients, nb_reqs))
    verify_sign_times = np.zeros((nb_run, nb_clients, nb_reqs))
    global_times = np.zeros(nb_run)

    for idx_run in range(nb_run):
        global_start = t.time()

        subscriptions = all_subscriptions

        SERVER = Server()
        s_time = t.time()
        (s_sk, s_pk) = Server.generate_ca(subscriptions)
        gen_key_times[idx_run] = t.time() - s_time

        c_subs = np.random.choice(subscriptions, int(np.ceil(.5 * len(subscriptions))), replace=False)
        
        for client_i in range(nb_clients):
            username = 'client_' + str(client_i)
            CLIENT = Client(username, c_subs)

            s_time = t.time()
            (issue_request, state) = CLIENT.prepare_registration(s_pk, username, CLIENT.subs_list)
            # assert jsonpickle.decode(issue_request) != None

            registration = SERVER.process_registration(s_sk, s_pk, issue_request, CLIENT.username, CLIENT.subs_list)
            # assert jsonpickle.decode(registration) != None
            
            credentials = CLIENT.process_registration_response(s_pk, registration, state)
            # assert jsonpickle.decode(credentials) != None
            register_times[idx_run, client_i] = t.time() - s_time
                
            # Generate a fixed request
            first_coord = np.random.uniform(46.5, 46.57) 
            second_coord = np.random.uniform(6.55, 6.65)
            message = (str(first_coord) + "," + str(second_coord)).encode('utf-8')
            types = np.random.choice(c_subs, int(np.ceil(.5 * len(c_subs))), replace=False)
            
            for req_i in range(nb_reqs):
                s_time = t.time()
                signature = CLIENT.sign_request(s_pk, credentials, message, types)
                # assert jsonpickle.decode(signature) != None
                show_creds_times[idx_run, client_i, req_i] = t.time() - s_time

                s_time = t.time()        
                result = SERVER.check_request_signature(s_pk, message, types, signature)
                # assert result
                verify_sign_times[idx_run, client_i, req_i] = t.time() - s_time

        global_times[idx_run] = t.time() - global_start

    return gen_key_times, register_times, show_creds_times, verify_sign_times, global_times

def eval_stroll_nb_client_nb_reqs(nb_run, nb_clients, nb_reqs_per_client):
    shape = (len(nb_clients), len(nb_reqs_per_client), nb_run)

    # gen_key_times = np.zeros(shape)
    # register_times = np.zeros(shape)
    # show_creds_times = np.zeros(shape)
    # verify_sign_times = np.zeros(shape)
    global_times = np.zeros(shape)

    for nb_cli_idx, nb_cli in enumerate(nb_clients):
        for nb_reqs_idx, nb_reqs in enumerate(nb_reqs_per_client):
            times = eval_stroll_global_time(nb_run, nb_cli, nb_reqs)
            # gen_key_times[nb_cli_idx, nb_reqs_idx, :] = times[0]
            # register_times[nb_cli_idx, nb_reqs_idx, :] = np.mean(times[1], axis=1) # mean by client

            # tmp = np.mean(times[2], axis=2)
            # show_creds_times[nb_cli_idx, nb_reqs_idx, :] = np.mean(tmp, axis=1)

            # tmp = np.mean(times[3], axis=2)
            # verify_sign_times[nb_cli_idx, nb_reqs_idx, :] = np.mean(tmp, axis=1) 
            
            global_times[nb_cli_idx, nb_reqs_idx, :] = times[4]

            print("#"*5, nb_cli, "clients with", nb_reqs, "requests", "#"*25)
            # print("\tGEN_KEYS:\t\t mean: {:13.5f} ms ; std: {:13.5f} ms".format(np.mean(gen_key_times[nb_cli_idx, nb_reqs_idx, :])*1e3, np.std(gen_key_times[nb_cli_idx, nb_reqs_idx, :])*1e3))
            # print("\tISSUANCE:\t\t mean: {:13.5f} ms ; std: {:13.5f} ms".format(np.mean(register_times[nb_cli_idx, nb_reqs_idx, :])*1e3, np.std(register_times[nb_cli_idx, nb_reqs_idx, :])*1e3))
            # print("\tSHOW_CREDS:\t\t mean: {:13.5f} ms ; std: {:13.5f} ms".format(np.mean(show_creds_times[nb_cli_idx, nb_reqs_idx, :])*1e3, np.std(show_creds_times[nb_cli_idx, nb_reqs_idx, :])*1e3))
            # print("\tVERIFY_SIGNED_REQUEST:\t mean: {:13.5f} ms ; std: {:13.5f} ms".format(np.mean(verify_sign_times[nb_cli_idx, nb_reqs_idx, :])*1e3, np.std(verify_sign_times[nb_cli_idx, nb_reqs_idx, :])*1e3))
            print("\tGLOBAL:\t\t\t mean: {:13.5f} ms ; std: {:13.5f} ms".format(np.mean(global_times[nb_cli_idx, nb_reqs_idx, :])*1e3, np.std(global_times[nb_cli_idx, nb_reqs_idx, :])*1e3))

def eval_stroll_fine_grained():
    subscriptions = all_subscriptions

    SERVER = Server()
    s_time = t.time()
    (s_sk, s_pk) = Server.generate_ca(subscriptions)
    gen_key_time = t.time() - s_time
    
    c_subs = np.random.choice(subscriptions, int(np.ceil(.5 * len(subscriptions))), replace=False)
    username = 'client'
    CLIENT = Client(username, c_subs)

    s_time = t.time()
    (issue_request, state) = CLIENT.prepare_registration(s_pk, username, CLIENT.subs_list)
    # assert jsonpickle.decode(issue_request) != None

    registration = SERVER.process_registration(s_sk, s_pk, issue_request, CLIENT.username, CLIENT.subs_list)
    # assert jsonpickle.decode(registration) != None
    
    credentials = CLIENT.process_registration_response(s_pk, registration, state)
    # assert jsonpickle.decode(credentials) != None
    register_time = t.time() - s_time
        
    message = "46.52345,6.57890".encode('utf-8')
    types = np.random.choice(c_subs, int(np.ceil(.5 * len(c_subs))), replace=False)
    
    s_time = t.time()
    signature = CLIENT.sign_request(s_pk, credentials, message, types)
    # assert jsonpickle.decode(signature) != None
    show_creds_time = t.time() - s_time

    s_time = t.time()        
    result = SERVER.check_request_signature(s_pk, message, types, signature)
    # assert result
    verify_sign_time = t.time() - s_time

    return gen_key_time, register_time, show_creds_time, verify_sign_time

if __name__ == '__main__':
    eval_multiple_run(eval_stroll_fine_grained, NB_RUN_FINE, "eval_stroll_fine_grained")
    
    print("#"*60)
    NB_CLIENTS = [1] + [i*10 for i in range(1,11)]
    NB_REQ_PER_CLIENT = [10]

    print("eval_stroll_coarse_grained".upper(), "with {} runs".format(NB_RUN_COARSE) )
    print("clients numbers:", NB_CLIENTS)
    print("requests numbers:", NB_REQ_PER_CLIENT)
    eval_stroll_nb_client_nb_reqs(NB_RUN_COARSE, NB_CLIENTS, NB_REQ_PER_CLIENT)

    print("#"*60)
    NB_CLIENTS = [10]
    NB_REQ_PER_CLIENT = [1] + [i*10 for i in range(1,11)]
    print("eval_stroll_coarse_grained".upper(), "with {} runs".format(NB_RUN_COARSE) )
    print("clients numbers:", NB_CLIENTS)
    print("requests numbers:", NB_REQ_PER_CLIENT)
    eval_stroll_nb_client_nb_reqs(NB_RUN_COARSE, NB_CLIENTS, NB_REQ_PER_CLIENT)