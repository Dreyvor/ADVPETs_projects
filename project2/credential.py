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

from typing import List, Tuple

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
IssueRequest = Tuple[G1Element,str]
BlindSignature = Tuple[Tuple[G1Element,G1Element],AttributeMap]
AnonymousCredential = Tuple[G1Element,AttributeMap]
DisclosureProof = Tuple[Tuple[G1Element,G1Element],Tuple[List[int],List[Attribute]],str]


######################
## SIGNATURE SCHEME ##
######################

def generate_key(
        attributes: List[Attribute]
    ) -> Tuple[SecretKey, PublicKey]:
    """ Generate signer key pair """
    
    L = len(attributes)
    
    # Group generators, public
    g = G1.generator()
    gt = G2.generator()
        
    # Generate secret and public keys
    x = G1.order().random() #secret
    X = g ** x #secret
    Xt = gt ** x #public
    
    y = np.empty((L,1),dtype=Bn) #secret
    Y = np.empty((L,1),dtype=G1Element) #public
    Yt = np.empty((L,1),dtype=G2Element) #public
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
    y = np.array(y).flatten()
    m = np.array([Bn.from_binary(m) for m in msgs])
    
    s = h ** (x+np.add.reduce(y*m))

    return (h,s)


def verify(
        pk: PublicKey,
        signature: Signature,
        msgs: List[bytes],
        att_map: AttributeMap = None
    ) -> bool:
    """ Verify the signature on a vector of messages """
    
    (h,s) = signature
    (g,Y,gt,Xt,Yt) = pk
    Yt = np.array(Yt).flatten()
    
    # Select the Yt appropriate for the attributes (using the attribute map)
    m = np.array([Bn.from_binary(m) for m in msgs])
    if(att_map != None):
        idx = [0] + [idx for (idx,val) in att_map.items() if val in m]
        Yt = Yt[idx] 
    
    if(h == G1.neutral_element):
        return False
    
    ym = Yt ** m
    
    return h.pair(Xt*np.multiply.reduce(ym)) == s.pair(gt)
    
    

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
        
    (x,X,y) = sk
    (g,Y,gt,Xt,Yt) = pk
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
    
    (g,Y,gt,Xt,Yt) = pk
    ((sigp1,sigp2),issuer_attributes) = response
    
    sig = (sigp1, sigp2/(sigp1**t))
    
    whole_attributes = {**issuer_attributes, **user_attributes}
    whole_attributes = dict(sorted(whole_attributes.items()))
    
    #add '0' in front of hex if not even length because bytes.fromhex() reads two digits hexa numbers
    ai = list(whole_attributes.values())
    ai_hex_pad = ['0'+Bn.hex(a) if len(Bn.hex(a))%2 != 0 else Bn.hex(a) for a in ai]
    ai = [bytes.fromhex(a) for a in ai_hex_pad] 
    
    # If sig is a valid signature for the attributes
    if(verify(pk,sig,ai,iss_att)):
        return (sig,whole_attributes)
    else:
        print("No credential obtained : could not verify signature")
        return None


## SHOWING PROTOCOL ##

def create_disclosure_proof(
        pk: PublicKey,
        credential: AnonymousCredential,
        hidden_attributes: AttributeMap
    ) -> DisclosureProof:
    """ Create a disclosure proof """
    
    (g,Y,gt,Xt,Yt) = pk
    ((sig1,sig2),ai) = credential
    
    # Prepare disclosed attributes
    ai = {int(k):v for (k,v) in ai.items()}
    disclosed_attributes_keys = [int(att) for att in ai if att not in hidden_attributes]
    disclosed_attributes_values = [ai.get(k) for k in disclosed_attributes_keys]
    
    #print("D_A_K : ", disclosed_attributes_keys)
    #print("D_A_V1 : ", disclosed_attributes_values)
    #print("HA : ", hidden_attributes)
    #print("AI : ", ai)
    
    t = G1.order().random()
    r = G1.order().random()
    while(sig1 ** r == G1.neutral_element): # r cannot be the neutral element
        r = G1.order().random()
    
    sigp1 = sig1 ** r
    sigp2 = (sig2*(sig1**t))**r
    sigp = (sigp1, sigp2)
    
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
    
    (g,Y,gt,Xt,Yt) = pk
    #((sigp1,sigp2),PI) = disclosure_proof
    #(da_keys, da_values) = disclosed_attributes
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