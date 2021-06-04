import credential as c
from petrelic.multiplicative.pairing import G1
from typing import List, Tuple, Dict, Union, Any


def separate_attributes(attributes: c.AttributeMap, idx: Union[List[int], range]) -> Tuple[c.AttributeMap, c.AttributeMap]:
    return [(key, value) for (key, value) in attributes if key in idx], [(key, value) for (key, value) in attributes if key not in idx]

def test_filterY():
    attributes = [(i, G1.order().random()) for i in range(30)]

    user_attributes, issuer_attributes = separate_attributes(attributes, list(range(15)))

    sk, pk = c.generate_key(attributes)

    filtered_attributes, _ = separate_attributes(user_attributes, [0, 1, 2, 3])

    res = c.filterY(pk[1], filtered_attributes)

    zipped = list(zip(pk[1][:4], [(i, a_i) for i, a_i in user_attributes[:4]]))

    reordered = [(i, Y_i, a_i) for (i, Y_i), (i_i, a_i) in zipped if i == i_i]

    assert res == reordered

def test_proof_of_commitment():
    attributes = [(i, G1.order().random()) for i in range(30)]

    user_attributes_index = list(range(15))

    user_attributes, issuer_attributes = separate_attributes(attributes, user_attributes_index)

    sk, pk = c.generate_key(attributes)

    # client computes proof
    request, t = c.create_issue_request(pk, user_attributes)
    # issuer verify proof
    res = c.verify_user_attributes_commit(pk, request)

    assert res

def test_full():
    all_subscriptions = ['appartment_block', 'bar', 'cafeteria', 'club', 'company', 'dojo', 'gym', 'laboratory',
                         'office', 'restaurant', 'supermarket', 'villa']

    subscription_map = {key: (all_subscriptions.index(key) + 1, G1.order().random()) for i, key in
                        enumerate(all_subscriptions)}

    attributes = [(0, G1.order().random())]+list(subscription_map.values())

    user_attributes_index = [0]

    user_attributes, issuer_attributes = separate_attributes(attributes, user_attributes_index)

    sk, pk = c.generate_key(attributes)

    # client computes proof
    request, t = c.create_issue_request(pk, user_attributes)

    response = c.sign_issue_request(sk, pk, request, all_subscriptions, subscription_map)

    assert response is not None

    signature = c.obtain_credential(pk, response, t, attributes)

    assert signature is not None