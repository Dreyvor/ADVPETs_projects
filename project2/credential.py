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

import numpy as np

import hashlib # for Fiat-Shamir heuristic

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
    
    y = [(i, G1.order().random()) for i, _ in attributes] # secret
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
    Yt = [(idx, val) for idx, val in Yt if idx in [k for k, _ in msgs]]
        
    ym = [Yt_i ** m_i for _, Yt_i, m_i in idx_zip(Yt, msgs)]
    
    return h.pair(Xt * G2.prod(ym)) == s.pair(gt)
    
    

#################################
## ATTRIBUTE-BASED CREDENTIALS ##
#################################

## ISSUANCE PROTOCOL ##
def create_issue_request(
        pk: PublicKey,
        user_attributes: AttributeMap
    ) -> Tuple[IssueRequest,Bn]:
    """ Create an issuance request

    This corresponds to the "user commitment" step in the issuance protocol.

    *Warning:* You may need to pass state to the `obtain_credential` function.
    """    
    (g,Y,_,_,_) = pk
    Y = np.array(Y)
    
    # Compute C
    t = G1.order().random() # will stay secret at client-side

    ai = np.array(list(user_attributes.values()))
    Yi = np.array(Y[list(user_attributes.keys())]).flatten()
    ya = np.multiply.reduce(Yi**ai)
    C = ((g**t) * ya)

    # Compute pi (commit to C using Fiat-Shamir heuristic)
    h = bytes(str(pk)+str(C),'utf-8')
    PI = hashlib.sha3_512(h).hexdigest()
    
    return ((C,PI),t)


def sign_issue_request(
        sk: SecretKey,
        pk: PublicKey,
        request: IssueRequest,
        issuer_attributes: AttributeMap
    ) -> BlindSignature:
    """ Create a signature corresponding to the user's request

    This corresponds to the "Issuer signing" step in the issuance protocol.
    """

    #TODO: check if valid signature

    (_,X,_) = sk
    (g,Y,_,_,_) = pk
    Y = np.array(Y)
    
    (C,PI) = request
    
    # Check commitment (Fiat-Shamir heuristic)
    h = bytes(str(pk)+str(C),'utf-8')
    PI_2 = hashlib.sha3_512(h).hexdigest()
    if(PI != PI_2):
        print("Cannot sign issue : could not verify proof of pi with respect to commitment C")
        return None
    
    # Compute sigma'
    u = G1.order().random()
    sig1 = g ** u
    
    ai = np.array(list(issuer_attributes.values()))
    Yi = np.array(Y[list(issuer_attributes.keys())]).flatten()
    ya = np.multiply.reduce(Yi**ai)
    
    sig2 = (X*C*ya) ** u
    
    sigp = (sig1,sig2)
    return (sigp,issuer_attributes)
    

def obtain_credential(
        pk: PublicKey,
        response: BlindSignature,
        t: Bn, #state from create_issue_request()
        user_attributes: AttributeMap, #to check signature
        iss_att: AttributeMap = None
    ) -> AnonymousCredential:
    """ Derive a credential from the issuer's response

    This corresponds to the "Unblinding signature" step.
    """
    
    ((sigp1,sigp2),issuer_attributes) = response
    
    sig = (sigp1, sigp2/(sigp1**t))
    
    whole_attributes = {**issuer_attributes, **user_attributes}
    whole_attributes = dict(sorted(whole_attributes.items()))
    
    #add '0' in front of hex if not even length because bytes.fromhex() reads two digits hexa numbers
    ai = list(whole_attributes.values())
    ai_hex_pad = ['0'+Bn.hex(a) if len(Bn.hex(a))%2 != 0 else Bn.hex(a) for a in ai]
    ai = [bytes.fromhex(a) for a in ai_hex_pad] 
    
    # If sig is a valid signature for the attributes
    if(verify(pk, sig, ai, iss_att)):
        return (sig, whole_attributes)
    else:
        print("No credential obtained : could not verify signature")
        return None


## SHOWING PROTOCOL ##

def create_disclosure_proof(
        pk: PublicKey,
        credential: AnonymousCredential,
        hidden_attributes: AttributeMap # attributes hidden from the verifier
    ) -> DisclosureProof:
    """ Create a disclosure proof """
    
    (_,_,gt,_,Yt) = pk
    ((sig1,sig2),ai) = credential
    
    t = G1.order().random()
    r = G1.order().random()
    while(sig1 ** r == G1.neutral_element): # r cannot be the neutral element
        r = G1.order().random()
    
    sigp1 = sig1 ** r
    sigp2 = (sig2*(sig1**t))**r
    sigp = (sigp1, sigp2)

    # Prepare disclosed attributes
    ai = {int(k):v for (k,v) in ai.items()}
    disclosed_attributes_keys = [int(att) for att in ai if att not in hidden_attributes]
    disclosed_attributes_values = [ai.get(k) for k in disclosed_attributes_keys]
    
    # PK of the disclosed attributes : with Fiat-Shamir heuristic
    ai_h = np.array(list(hidden_attributes.values()))
    Yti = np.array([Yt[i] for i in list(hidden_attributes.keys())]).flatten()
    e_Yt = np.array([sigp1.pair(yti) for yti in Yti])

    sigp1_yit_ai = e_Yt ** ai_h
    p = ((sigp1.pair(gt))**t) * np.multiply.reduce(sigp1_yit_ai) 
    h = bytes(str(pk)+str(disclosed_attributes_values)+str(p),'utf-8')
    
    PI = hashlib.sha3_512(h).hexdigest()
    
    return (sigp, PI)

def verify_disclosure_proof(
        pk: PublicKey,
        disclosure_proof: DisclosureProof,
        revealed_att: AttributeMap
    ) -> bool:
    """ Verify the disclosure proof

    Hint: The verifier may also want to retrieve the disclosed attributes
    """
    
    (_,_,gt,Xt,Yt) = pk
    ((sigp1,sigp2), PI) = disclosure_proof
    da_keys = list(revealed_att.keys())
    da_values = list(revealed_att.values())
    
    if(sigp1 == G1.neutral_element):
        return False
    
    # Verify the PK, (Fiat-Shamir)
    ai_d = np.array(da_values)
    Yti = np.array([Yt[i] for i in da_keys]).flatten()
    e_Yt = np.array([sigp1.pair(yti) for yti in Yti])
    sigp1_yit_ai = e_Yt ** (-ai_d)
    p = sigp2.pair(gt) * np.multiply.reduce(sigp1_yit_ai) / sigp1.pair(Xt)
    h = bytes(str(pk)+str(da_values)+str(p),'utf-8')
    PI2 = hashlib.sha3_512(h).hexdigest()
    
    return PI == PI2


#############
## HELPERS ##
#############

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