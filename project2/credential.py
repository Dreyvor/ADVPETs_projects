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

from typing import Any, List, Tuple

from serialization import jsonpickle

from petrelic.multiplicative.pairing import G1, G2, GT
from petrelic.multiplicative.pairing import G1Element, G2Element
from petrelic.bn import Bn

import numpy as np

from typing import Dict

import hashlib # for Fiat-Shamir heuristic

# Type hint aliases
# Feel free to change them as you see fit.
# Maybe at the end, you will not need aliases at all!
SecretKey = Tuple[Bn,G1Element,List[Bn]]
PublicKey = Tuple[G1Element,List[G1Element],G2Element,G2Element,List[G2Element]]
Signature = Tuple[G1Element,G1Element]
Attribute = Bn
AttributeMap = Dict[int,Attribute] 
IssueRequest = Any #Tuple[G1Element,Tuple[]]]
BlindSignature = Tuple[G1Element,G1Element,AttributeMap]
AnonymousCredential = [G1Element,List[Attribute]]
DisclosureProof = Any


######################
## SIGNATURE SCHEME ##
######################

def generate_key(
        attributes: List[Attribute]
    ) -> Tuple[SecretKey, PublicKey]:
    """ Generate signer key pair """
    
    L = len(attributes)
    
    # Random group generators, public
    g = get_random_G1_different_from()
    gt = get_random_G2_different_from()
        
    # Generate secret and public keys
    x = G1.order().random() #secret
    X = g ** x #secret
    Xt = gt ** x #public
    
    y = np.array((L,1),dtype=Bn) #secret
    Y = np.array((L,1),dtype=G1Element) #public
    Yt = np.array((L,1),dtype=G2Element) #public
    for i in range(L):
        y[i] = G1.order().random()
        Y[i] = g ** y[i]
        Yt[i] = gt ** y[i]
    
    pk = (g,Y.tolist(),gt,Xt,Yt.tolist())
    sk = (x,X,y.tolist())
    
    return (sk,pk)


def sign(
        sk: SecretKey,
        msgs: List[bytes]
    ) -> Signature:
    """ Sign the vector of messages `msgs` """
    
    # h a random generator (check that it is not the neutral element)
    h = get_random_G1_different_from()

    (x,X,y) = sk
    y = np.array(y)
    m = np.array([Bn.from_binary(m) for m in msgs])
    
    s = h ** (x+np.add.reduce(y*m))

    return (h,s)


def verify(
        pk: PublicKey,
        signature: Signature,
        msgs: List[bytes]
    ) -> bool:
    """ Verify the signature on a vector of messages """

    (h,s) = signature
    (g,Y,gt,Xt,Yt) = pk
    
    if(h == G1.neutral_element):
        return False
    
    m = np.array([Bn.from_binary(m) for m in msgs])
    
    ym = Yt ** m
    
    if(h.pair(Xt*np.multiply.reduce(ym)) != s.pair(gt)):
        return False
    
    return True
    
    

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
    
    (g,Y,gt,Xt,Yt) = pk
    Y = np.array(Y)
    
    # Compute C
    t = G1.order().random()
    gt = g**t
    
    ai = np.array(list(user_attributes.values()))
    Yi = Y[list(user_attributes.keys())]
    ya = np.multiply.reduce(Yi**ai)
    C = gt * ya
    
    # Compute pi (Fiat-Shamir heuristic)
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
    
    (x,X,y) = sk
    (g,Y,gt,Xt,Yt) = pk
    Y = np.array(Y)
    
    (C,PI) = request
    
    # Check commitment (Fiat-Shamir heuristic)
    h = bytes(str(pk)+str(C),'utf-8')
    PI_2 = hashlib.sha3_512(h).hexdigest()
    if(PI != PI_2):
        return None
    
    # Compute sigma'
    u = G1.order().random()
    sig1 = g ** u
    
    ai = np.array(list(issuer_attributes.values()))
    Yi = Y[list(issuer_attributes.keys())]
    ya = np.multiply.reduce(Yi**ai)
    
    sig2 = (X*C*ya) ** u
    
    return (sig1,sig2,issuer_attributes)
    

def obtain_credential(
        pk: PublicKey,
        response: BlindSignature,
        t: Bn, #state from create_issue_request()
        user_attributes: AttributeMap #to check signature
    ) -> AnonymousCredential:
    """ Derive a credential from the issuer's response

    This corresponds to the "Unblinding signature" step.
    """
    
    (sig1,sig2,issuer_attributes) = response
    
    sig = (sig1,sig2/(sig1**t))
     
    whole_attributes = {**issuer_attributes, **user_attributes}
    whole_attributes = dict(sorted(whole_attributes.items()))

    ai = list(whole_attributes.values())    
    ai = [bytes.fromhex('0'+Bn.hex(a)) for a in ai] #add '0' bc fromhex reads two digits hexa numbers
    
    # If sig is a valid signature for the attributes
    if(verify(pk,sig,ai)):
        return (sig,ai)
    else:
        return None


## SHOWING PROTOCOL ##

def create_disclosure_proof(
        pk: PublicKey,
        credential: AnonymousCredential,
        hidden_attributes: List[Attribute],
        message: bytes
    ) -> DisclosureProof:
    """ Create a disclosure proof """
    raise NotImplementedError()


def verify_disclosure_proof(
        pk: PublicKey,
        disclosure_proof: DisclosureProof,
        message: bytes
    ) -> bool:
    """ Verify the disclosure proof

    Hint: The verifier may also want to retrieve the disclosed attributes
    """
    raise NotImplementedError()


## HELPER FUNCTIONS ##

# Return a random element of G1 different from the neutral element and another given element as parameter
def get_random_G1_different_from(elem=G1.neutral_element):
    rdm = G1.generator() ** G1.order().random()
    while(rdm == G1.neutral_element or rdm.eq(elem)):
        rdm = G1.generator() ** G1.order().random()
    return rdm

# Same as 'get_random_G1_different_from()' but with G2
def get_random_G2_different_from(elem=G2.neutral_element):
    rdm = G2.generator() ** G2.order().random()
    while(rdm == G2.neutral_element or rdm.eq(elem)):
        rdm = G2.generator() ** G2.order().random()
    return rdm