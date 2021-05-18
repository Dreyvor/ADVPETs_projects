"""
Classes that you need to complete.
"""

from typing import Any, Dict, List, Union, Tuple

# Optional import
from serialization import jsonpickle
import credential as c

# Type aliases
State = Tuple[c.Bn,c.SecretKey]

SubscriptionMap = Dict[str, Tuple[int,c.Attribute]]

#all_subscriptions = ['appartment_block', 'bar', 'cafeteria', 'club', 'company', 'dojo', 'gym', 'laboratory', 'office',
                     'restaurant', 'supermarket', 'villa']

class Server:
    """Server"""


    def __init__(self):
        """
        Server constructor.
        """
        self.valid_sub: SubscriptionMap = {}


    @staticmethod
    def generate_ca(
            subscriptions: List[str]
        ) -> Tuple[bytes, bytes]:
        """Initializes the credential system. Runs exactly once in the
        beginning. Decides on schemes public parameters and choses a secret key
        for the server.

        Args:
            subscriptions: a list of all valid attributes. Users cannot get a
                credential with a attribute which is not included here.

        Returns:
            tuple containing:
                - server's secret key
                - server's pubic information
            You are free to design this as you see fit, but the return types
            should be encoded as bytes.
        """
        
        valid_sub: SubscriptionMap = {}
        for i in range(len(subscriptions)):
             valid_sub[subscriptions[i]] = (i+1,c.G1.order().random()) #i+1 because 0 is for the user
        
        att = list(valid_sub.values()) + [(0,None)]
        (sk_s,pk_s) = c.generate_key(att)
        
        return (jsonpickle.encode((sk_s,valid_sub)),jsonpickle.encode(pk_s))
        

    def process_registration(
            self,
            server_sk: bytes,
            server_pk: bytes,
            issuance_request: bytes,
            username: str,
            subscriptions: List[str]
        ) -> bytes:
        """ Registers a new account on the server.

        Args:
            server_sk: the server's secret key (serialized)
            issuance_request: The issuance request (serialized)
            username: username
            subscriptions: attributes


        Return:
            serialized response (the client should be able to build a
                credential with this response).
        """
        
        (s_sk,valid_sub) = jsonpickle.decode(server_sk)
        self.valid_sub = valid_sub
        
        s_pk: c.PublicKey = jsonpickle.decode(server_pk)
        
        # Issuer attributes
        iss_att = [att for (k,att) in valid_sub if k not in subscriptions]
        
        # Recover C and PI, decode
        req: c.IssueRequest  = jsonpickle.decode(issuance_request)
        #separation = bytearray('separation','utf-8')
        #idx = req.find(separation)
        #C_enc = req[0:idx]
        #C = c.G1Element.from_binary(C_enc.decode('utf-8'))        
        #PI_enc = req[idx+len(separation):len(issuance_request)]
        #PI = PI_enc.decode('utf-8')
        
        signed_req = c.sign_issue_request(s_sk,s_pk,req,iss_att)
        
        # Encode response
        #sig1_enc = c.G1Element.to_binary(sig1)
        #sig2_enc = c.G1Element.to_binary(sig2)
        #issuer_attributes_enc = bytearray(str(issuer_attributes),'utf-8')
        #separation1 = bytearray('separation1','utf-8')
        #separation2 = bytearray('separation2','utf-8')
        
        return jsonpickle.encode(signed_req)

    def check_request_signature(
        self,
        server_pk: bytes,
        message: bytes,
        revealed_attributes: List[str],
        signature: bytes
        ) -> bool:
        """ Verify the signature on the location request

        Args:
            server_pk: the server's public key (serialized)
            message: The message to sign
            revealed_attributes: revealed attributes
            signature: user's authorization (serialized)

        Returns:
            whether a signature is valid
        """
        ###############################################
        # TODO: Complete this function.
        ###############################################
        raise NotImplementedError


class Client:
    """Client"""

    def __init__(self):
        """
        Client constructor.
        """

    def prepare_registration(
            self,
            server_pk: bytes,
            username: str,
            subscriptions: List[str]
        ) -> Tuple[bytes, State]:
        """Prepare a request to register a new account on the server.

        Args:
            server_pk: a server's public key (serialized)
            username: user's name
            subscriptions: user's subscriptions

        Return:
            A tuple containing:
                - an issuance request
                - A private state. You can use state to store and transfer information
                from prepare_registration to proceed_registration_response.
                You need to design the state yourself.
        """
        # Secret key of client
        sk_c = c.G1.order().random()
        user_att = [(0,sk_c)]
        
        valid_sub: SubscriptionMap = {}
        for i in range(len(subscriptions)):
             valid_sub[subscriptions[i]] = (i,c.G1.order().random())
        
        # Create the request
        server_pk = jsonpickle.decode(server_pk)
        (req,t) = c.create_issue_request(server_pk,user_att)
        
        # Save t and the secret key in the state
        state = (t,sk_c)
        
        # Request into jsonpickle, add a separation to distinguish C and PI
        #(C,PI) = req
        #PI_byte = bytearray(PI,'utf-8')
        #separation = bytearray('separation','utf-8')
        #C_byte = c.G1Element.to_binary(C) #bytearray(str(c.G1Element.to_binary(C)),'utf-8')
        
        req = jsonpickle.encode(req)
        
        return (req,state)

    def process_registration_response(
            self,
            server_pk: bytes,
            server_response: bytes,
            private_state: State
        ) -> bytes:
        """Process the response from the server.

        Args:
            server_pk a server's public key (serialized)
            server_response: the response from the server (serialized)
            private_state: state from the prepare_registration
            request corresponding to this response

        Return:
            credentials: create an attribute-based credential for the user
        """
        # Get private state
        (t,sk) = private_state
        
        # Parse server response
        ((sig1,sig2),iss_att) = jsonpickle.decode(server_response)
        #separation1 = bytearray('separation1','utf-8')
        #separation2 = bytearray('separation2','utf-8')
        #idx1 = server_response.find(separation1)
        #idx2 = server_response.find(separation2)        
        #sig1 = server_response[0:idx1]
        #sig2 = server_response[idx1+len(separation1):idx2]
        #iss_att = server_response[idx2+len(separation2):len(server_response)]
        
        # Decode server response
        #sig1 = c.G1Element.to_binary(sig1.decode('utf-8'))
        #sig2 = c.G1Element.to_binary(sig2.decode('utf-8'))
        #iss_att = eval(iss_att.decode('utf-8'))
        
        # Obtain credentials
        credential = c.obtain_credential(server_pk,((sig1,sig2),iss_att),t,self.user_att)
        self.credential = (credential,sk)
        
        ((sig1,sig2),att) = credential
        
        #sig1_byte = c.G1Element.to_binary(sig1)
        #sig2_byte = c.G1Element.to_binary(sig2)
        #att_byte = bytearray(str(att),'utf-8')
        #cred_bytes = sig1_byte + separation1 + sig2_byte + separation2 + att_byte
        
        return jsonpickle.encode(cred_bytes)
        
    def sign_request(
            self,
            server_pk: bytes,
            credentials: bytes,
            message: bytes,
            types: List[str]
        ) -> bytes:
        """Signs the request with the client's credential.

        Arg:
            server_pk: a server's public key (serialized)
            credential: client's credential (serialized)
            message: message to sign
            types: which attributes should be sent along with the request?

        Returns:
            A message's signature (serialized)
        """
        ###############################################
        # TODO: Complete this function.
        ###############################################
        raise NotImplementedError
