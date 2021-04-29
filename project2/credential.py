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

# Type hint aliases
# Feel free to change them as you see fit.
# Maybe at the end, you will not need aliases at all!
SecretKey = Tuple[Bn,G1Element,List[Bn]]
PublicKey = Tuple[G1Element,List[G1Element],G2Element,G2Element,List[G2Element]]
Signature = Tuple[G1Element,G1Element]
Attribute = Bn
AttributeMap = List[Bn]
IssueRequest = Any
BlindSignature = Any
AnonymousCredential = Any
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
    g = G1.generator() ** G1.order().random()
    gt = G2.generator() ** G2.order().random()
    while(g == G1.neutral_element): # cannot be the neutral element
        g = G1.generator() ** G1.order().random()
    while(gt == G2.neutral_element): # cannot be the neutral element
        gt = G2.generator() ** G2.order().random()
        
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
    h = G1.generator() ** G1.order().random()
    while(h == G1.neutral_element):
        h = G1.generator() ** G1.order().random()

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
    ) -> IssueRequest:
    """ Create an issuance request

    This corresponds to the "user commitment" step in the issuance protocol.

    *Warning:* You may need to pass state to the `obtain_credential` function.
    """    
    raise NotImplementedError()
    

def sign_issue_request(
        sk: SecretKey,
        pk: PublicKey,
        request: IssueRequest,
        issuer_attributes: AttributeMap
    ) -> BlindSignature:
    """ Create a signature corresponding to the user's request

    This corresponds to the "Issuer signing" step in the issuance protocol.
    """
    raise NotImplementedError()


def obtain_credential(
        pk: PublicKey,
        response: BlindSignature
    ) -> AnonymousCredential:
    """ Derive a credential from the issuer's response

    This corresponds to the "Unblinding signature" step.
    """
    raise NotImplementedError()


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
