"""
Skeleton credential module for implementing PS credentials

The goal of this skeleton is to help you implementing PS credentials. Following
this API is not mandatory and you can change it as you see fit. This skeleton
only provides major functionality that you will need.

You will likely have to define more functions and/or classes. In particular, to
maintain clean code, we recommend to use classes for things that you want to
send between parties. You can then use `jsonpickle` serialization to convert
these classes to byte arrays (as expected by the other classes) and back again.

We also avoided the use of classes in this template so that the code more closely
resembles the original scheme definition. However, you are free to restructure
the functions provided to resemble a more object-oriented interface.
"""

from typing import List, Tuple, Dict, Union, Any

from petrelic.multiplicative.pairing import G1, G2, GT
from petrelic.multiplicative.pairing import G1Element, G2Element
from petrelic.bn import Bn

import hashlib as hlib

# Type hint aliases
# Feel free to change them as you see fit.
# Maybe at the end, you will not need aliases at all!
SecretKey = Tuple[Bn, G1Element, List[Tuple[int, Bn]]]
PublicKey = Tuple[G1Element, List[Tuple[int, G1Element]], G2Element, G2Element, List[Tuple[int, G2Element]]]
Signature = Tuple[G1Element, G1Element]
Attribute = Bn
AttributeMap = List[Tuple[int, Attribute]]
ProofCommit = Tuple[G1Element, List[Tuple[int, G1Element]], Bn, Bn, List[Tuple[int, Bn]]]
IssueRequest = Tuple[G1Element, ProofCommit]
BlindSignature = Tuple[G1Element, G1Element]
AnonymousCredential = Tuple[Signature, AttributeMap]
DisclosureProof = Tuple[Signature, AttributeMap, G2Element, List[Tuple[int, G2Element]], Bn, Bn, List[Tuple[int, Bn]]]


######################
## SIGNATURE SCHEME ##
######################

def generate_key(
        attributes: AttributeMap
    ) -> Tuple[SecretKey, PublicKey]:
    """ Generate signer key pair """

    # Group generators, public
    g = G1.generator()
    gt = G2.generator()
        
    # Generate secret and public keys
    x = G1.order().random() #secret
    X = g ** x #secret
    Xt = gt ** x #public
    
    y = [(i, G1.order().random()) for i, _ in attributes] #secret
    Y = [(i, g ** y_i) for i, y_i in y] #public
    Yt = [(i, gt ** y_i) for i, y_i in y] #public

    sk = (x, X, y)
    pk = (g, Y, gt, Xt, Yt)
    
    return (sk, pk)


def sign(
        sk: SecretKey,
        msgs: AttributeMap
    ) -> Union[Signature, None]:
    """ Sign the vector of messages `msgs` """
    
    (x,_,y) = sk

    if len(y) < len(msgs):
        print("ERR: Too much attributes in the msgs to be able to sign.")
        return None

    # h a random generator (check that it is not the neutral element)
    h = G1.generator() ** G1.order().random()
    while(h == G1.neutral_element):
        h = G1.generator() ** G1.order().random()
        
    s = h ** (x + sum([y_i * m_i for _, y_i, m_i in idx_zip(y, msgs)]))

    return (h, s)


def verify(
        pk: PublicKey,
        signature: Signature,
        msgs: AttributeMap,
    ) -> bool:
    """ Verify the signature on a vector of messages """
    
    (h, s) = signature
    (_, _, gt, Xt, Yt) = pk

    if h == G1.neutral_element or (len(Yt) < len(msgs)):
        return False
    
    # Select the Yt appropriate for the attributes
    ym = [Yt_i ** m_i for _, Yt_i, m_i in filterY(Yt, msgs)]
    
    return h.pair(Xt * G2.prod(ym)) == s.pair(gt)



#################################
## ATTRIBUTE-BASED CREDENTIALS ##
#################################

## ISSUANCE PROTOCOL ##
def create_issue_request(
        pk: PublicKey,
        user_attributes: AttributeMap
    ) -> Tuple[IssueRequest, Bn]:
    """ Create an issuance request

    This corresponds to the "user commitment" step in the issuance protocol.

    *Warning:* You may need to pass state to the `obtain_credential` function.
    """

    (g,Y,_,_,_) = pk
    
    # Compute C
    t = G1.order().random() # will stay secret at client-side

    ya = G1.prod([Yi ** ai for _, Yi, ai in filterY(Y, user_attributes)])

    commitment = ((g ** t) * ya)

    # Generate the zkp
    zkp = generate_zkp_prover_side(pk, t, user_attributes, commitment)

    return ((commitment, zkp), t)


def sign_issue_request(
        sk: SecretKey,
        pk: PublicKey,
        request: IssueRequest,
        subscriptions: List[str],
        server_supported: Dict[str, Tuple[int, Bn]]
    ) -> Union[BlindSignature, None]:
    """ Create a signature corresponding to the user's request

    This corresponds to the "Issuer signing" step in the issuance protocol.
    """

    if not verify_user_attributes_commit(pk, request):
        return None

    (_,X,_) = sk
    (g,Y,_,_,_) = pk
    
    (C, zkp) = request
    
    # Compute both sigma prime
    u = G1.order().random()
    sigp1 = g ** u
    
    issuer_attributes_for_client = [server_supported[e] for e in subscriptions]

    ya = G1.prod([Yi ** ai for _, Yi, ai in filterY(Y, issuer_attributes_for_client)])
    
    sigp2 = (X*C*ya) ** u
    
    return (sigp1, sigp2)

def obtain_credential(
        pk: PublicKey,
        response: BlindSignature,
        t: Bn, #state from create_issue_request()
        attributes: AttributeMap, #to check signature
    ) -> Union[AnonymousCredential, None]:  
    """ Derive a credential from the issuer's response

    This corresponds to the "Unblinding signature" step.
    """
    
    (sigp1, sigp2) = response
    
    sig = (sigp1, sigp2/(sigp1**t))
        
    # If sig is not a valid signature for the attributes, then return an error
    if not verify(pk, sig, attributes) or (sigp1 == G1.unity()):
        print("ERR: No credential obtained: could not verify signature")
        return None

    return (sig, attributes)


######################
## SHOWING PROTOCOL ##
######################

def create_disclosure_proof(
        pk: PublicKey,
        credential: AnonymousCredential,
        hidden_attributes: AttributeMap # attributes hidden from the verifier
    ) -> DisclosureProof:
    """ Create a disclosure proof """
    
    (g, Y, gt, Xt, Yt) = pk
    ((sig1, sig2), ais) = credential
    
    # Generate both sigma prime and combine them to generate a randomized signature
    t = G1.order().random()
    r = G1.order().random()
    while(sig1 ** r == G1.neutral_element): # r cannot be the neutral element
        r = G1.order().random()
    
    sigp1 = sig1 ** r
    sigp2 = (sig2*(sig1**t))**r
    sigp = (sigp1, sigp2)

    # Prepare disclosed attributes
    hidden_attributes_idx = [i for i, _ in hidden_attributes]
    disclosed_attributes = [(i, a_i) for i, a_i in ais if i not in hidden_attributes_idx]

    ### ZKP for the attributes disclosure, prover side
    # pick random big numbers for t and for all hidden attributes
    rnd_t = G2.order().random()
    Rnd_t = gt ** rnd_t

    rnd_is = [(i, G2.order().random()) for i, _ in hidden_attributes]
    Rnd_is = [(i, sigp1 ** x) for i, x in rnd_is]

    # Create the challenge
    h_Rnd_t = hash_sha(Rnd_t)
    h_pk = hash_pk(pk)
    h_Rnd_is = hash_Rnd_is(Rnd_is)
    h_disclosed_atts = sum([hash_sha(a_i) for _, a_i in disclosed_attributes])
    h_sigp1 = hash_sha(sigp1)
    h_sigp2 = hash_sha(sigp2)
    challenge = Bn(abs(h_Rnd_t + h_pk + h_Rnd_is + h_disclosed_atts + h_sigp1 + h_sigp2))

    # compute answer to challenge
    s_t = rnd_t * challenge + t

    s_is = [(i, rnd_i * challenge + a_i) for i, rnd_i, a_i in idx_zip(rnd_is, hidden_attributes)]

    return (sigp, disclosed_attributes, (Rnd_t, Rnd_is, challenge, s_t, s_is))


def verify_disclosure_proof(
        pk: PublicKey,
        disclosure_proof: DisclosureProof,
        hidden_attributes: AttributeMap
    ) -> bool:
    """ Verify the disclosure proof

    Hint: The verifier may also want to retrieve the disclosed attributes
    """
    
    (g, Y, gt, Xt, Yt) = pk
    ((sigp1, sigp2), disclosed_attributes, (Rnd_t, Rnd_is, challenge, s_t, s_is)) = disclosure_proof
    
    if sigp1 == G1.unity():
        return False

    # check the challenge
    h_Rnd_t = hash_sha(Rnd_t)
    h_pk = hash_pk(pk)
    h_Rnd_is = hash_Rnd_is(Rnd_is)
    h_disclosed_atts = sum([hash_sha(a_i) for _, a_i in disclosed_attributes])
    h_sigp1 = hash_sha(sigp1)
    h_sigp2 = hash_sha(sigp2)
    c_p = Bn(abs(h_Rnd_t + h_pk + h_Rnd_is + h_disclosed_atts + h_sigp1 + h_sigp2))

    if c_p != challenge:
        return False

    # check zkp
    sigma_left = sigp2.pair(gt)

    sigma_right = sigp1.pair((gt ** s_t) / (Rnd_t ** challenge))
    sigma_right *= sigp1.pair(Xt)
    sigma_right *= GT.prod([sigp1.pair(Yt_i ** a_i) for _, Yt_i, a_i in filterY(Yt, disclosed_attributes)])

    hid_idx = [idx for idx, _ in hidden_attributes]
    hidden_Yt = [(i, Yt_i) for i, Yt_i in Yt if i in hid_idx]

    sigma_right *= GT.prod([((sigp1 ** s_i) / Rnd_i ** challenge).pair(Yt_i) for i, s_i, Rnd_i, Yt_i in idx_zip(s_is, Rnd_is, hidden_Yt)])

    return sigma_left == sigma_right


#############
## HELPERS ##
#############

def hash_sha(a):
    """ TODO: Write descritption """
    return int.from_bytes(hlib.sha3_512(str(a).encode()).digest(), 'big')

def hash_Rnd_is(Rnd_is: Union[List[Tuple[int, G1Element]], List[Tuple[int, G2Element]]]) -> int:
    """ TODO: Write descritption """
    return sum([hash_sha(Rnd_i) for _, Rnd_i in Rnd_is])

def hash_pk(pk: PublicKey) -> int:
    """ TODO: Write descritption """
    (g, Y, gt, Xt, Yt) = pk

    c = hash_sha(g) + hash_sha(gt) + hash_sha(Xt)

    for e in Y:
        c += hash_sha(e)

    for e in Yt:
        c += hash_sha(e)

    return c    

def idx_zip(a: List[Tuple[int, Any]],
            b: List[Tuple[int, Any]],
            c: List[Tuple[int, Any]] = None) -> Union[
    List[Tuple[int, Any, Any]], List[Tuple[int, Any, Any, Any]], None]:
    """ TODO: Write descritption """

    idx_a = [i for i, _ in a]
    idx_b = [i for i, _ in b]

    if not idx_a.sort() == idx_b.sort():
        return None

    a.sort(key = lambda e: e[0])
    b.sort(key = lambda e: e[0])

    zipped_res = zip(a, b)

    if c is not None:
        idx_c = [i for i, _ in c]
        if not idx_c.sort() == idx_a.sort():
            return None

        c.sort(key=lambda e: e[0])
        zipped_res = zip(zipped_res, c)

        return [(i, a_i, b_i, c_i) for ((i, a_i), (_, b_i)), (_, c_i) in zipped_res]

    return [(i, a_i, b_i) for (i, a_i), (_, b_i) in zipped_res]

def filterY(Y: Union[List[Tuple[int, G1Element]], List[Tuple[int, G2Element]]], attributes: AttributeMap) -> Union[
    List[Tuple[int, G1Element, Bn]], List[Tuple[int, G2Element, Bn]]]:
    """TODO: Write description"""
    filtered_Y = [(i, Y_i) for i, Y_i in Y if i in [k for k, _ in attributes]]
    return idx_zip(filtered_Y, attributes)

def generate_zkp_prover_side(
        pk: PublicKey,
        t: Bn,
        user_attributes: AttributeMap,
        commitment: G1Element) -> ProofCommit:
    """TODO: Write description"""

    (g, Y, _, _, _) = pk

    # pick random big numbers for t and for all attributes
    rnd_t = G1.order().random()
    Rnd_t = g ** rnd_t

    rnd_is = [(i, G1.order().random()) for i, _ in user_attributes]
    Rnd_is = [(i, Y_i ** rnd_i) for i, Y_i, rnd_i in filterY(Y, rnd_is)]

    # Create the challenge
    h_Rnd_t = hash_sha(Rnd_t)
    h_pk = hash_pk(pk)
    h_Rnd_is = hash_Rnd_is(Rnd_is)
    h_commit = hash_sha(commitment)

    challenge = Bn(abs(h_Rnd_t + h_pk + h_Rnd_is + h_commit))

    # Answers to challenge
    s_t = rnd_t + challenge * t
    s_is = [(i, rnd_i + challenge * a_i) for i, rnd_i, a_i in idx_zip(rnd_is, user_attributes)]

    return Rnd_t, Rnd_is, challenge, s_t, s_is

def verify_user_attributes_commit(
        pk: PublicKey,
        request: IssueRequest) -> bool:
    """ TODO: Write description """

    (g, Y, _, _, _) = pk
    (commitment, (Rnd_t, Rnd_is, challenge, s_t, s_is)) = request

    h_Rnd_t = hash_sha(Rnd_t)
    h_pk = hash_pk(pk)
    h_Rnd_is = hash_Rnd_is(Rnd_is)
    h_commit = hash_sha(commitment)

    c_p = Bn(abs(h_Rnd_t + h_pk + h_Rnd_is + h_commit))

    if challenge != c_p:
        return False

    # check proof
    Rnd_is_mult = G1.prod([Rnd_i for _, Rnd_i in Rnd_is])
    sig1 = (commitment ** challenge) * Rnd_t * Rnd_is_mult

    sig2 = g ** s_t
    sig2 *= G1.prod([Y_i ** s_i for _, Y_i, s_i in filterY(Y, s_is)])

    return sig1 == sig2