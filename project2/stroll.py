"""
Classes that you need to complete.
"""

from typing import Any, Dict, List, Union, Tuple
from petrelic.multiplicative.pairing import G1, G2, GT
from petrelic.bn import Bn

from serialization import jsonpickle
import credential as c

# Type aliases
State = Tuple[Bn, Bn]

SubscriptionMap = Dict[str, Tuple[int, c.Attribute]]

all_possible_subs = ['appartment_block', 'bar', 'cafeteria',
                    'club', 'company', 'dojo', 'gym', 'laboratory',
                    'office', 'restaurant', 'supermarket', 'villa']

class Server:
    """Server"""

    def __init__(self):
        """
        Server constructor.
        """
        self.valid_sub: SubscriptionMap = {} # will contain (SubscriptionName : (idx, attribute))
        self.subscribers: Dict[str, List[str]] = {} # will contain (Username : ListOfSubscriptionsStrings)

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
        for sub in [key for key in subscriptions if ((key in all_possible_subs) and (not key == 'username'))]:
                valid_sub[sub] = (all_possible_subs.index(sub) + 1, c.G1.order().random()) # "+1" because 0 is for the user
        
        att = [(0, None)] + list(valid_sub.values())
        (sk_s, pk_s) = c.generate_key(att)
        
        return (jsonpickle.encode((sk_s, valid_sub)).encode(), jsonpickle.encode(pk_s).encode())
        

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
            public_sk: the server's public key (serialized)
            issuance_request: The issuance req uest (serialized)
            username: username
            subscriptions: user's subscriptions

        Return:
            serialized response (the client should be able to build a
                credential with this response).
        """
        
        (sk_s, valid_sub) = jsonpickle.decode(server_sk)
        
        if len(self.valid_sub) == 0: # Does not replace the server subs list if it has already been initialized
            self.valid_sub = valid_sub
        
        pk_s = jsonpickle.decode(server_pk)
        
        # If a user's subscriptions is not in the list of valid attributes return None
        valid_keys = list(self.valid_sub.keys())
        is_valid = all(sub in valid_keys for sub in subscriptions)
        if not is_valid:
            print("ERR: Items in subscription not valid")
            return jsonpickle.encode(None).encode()
        
        # Issuer attributes, create an AttributeMap from valid subscriptions
        iss_att = [v for k, v in valid_sub.items() if k in subscriptions]
        
        # Decode the issue request
        req: c.IssueRequest  = jsonpickle.decode(issuance_request)
        if req == None:
            return jsonpickle.encode(None).encode()

        # Sign it
        signed_req = c.sign_issue_request(sk_s, pk_s, req, subscriptions, valid_sub)
        if signed_req == None:
            return jsonpickle.encode(None).encode()

        # If the request was a valid one, then return the signed request with the issuer attributes and keep a record of the subscription
        if username in self.subscribers:
            self.subscribers[username] = list( set(self.subscribers[username]) | set(subscriptions) ) # union of both list without duplicates
        else:
            self.subscribers[username] = subscriptions

        return jsonpickle.encode((signed_req, iss_att)).encode()

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
        # Deserialization
        s_pk = jsonpickle.decode(server_pk)
        signature = jsonpickle.decode(signature)
        if signature == None:
            print("ERR: Signature is None")
            return False
        
        is_valid = all(sub in self.valid_sub.keys() for sub in revealed_attributes)
        if not is_valid:
            print("ERR: Cannot request one or more of these attributes")
            return False
        
        # Check the proof
        (client_signature, disc_proof) = signature
        
        revealed_att_map = [att for sub, att in self.valid_sub.items() if sub in revealed_attributes]

        # TODO: How to retrieve [(0, Whatever)] in a nice form?
        user_att_idx = 0
        proof_res = c.verify_disclosure_proof(s_pk, disc_proof, [(user_att_idx, None)])
        if not proof_res:
            print("ERR: Wrong proof")
            return False

        ((sigp1, _), disclosed_attributes, (_, Rnd_is, challenge, _, s_is)) = disc_proof

        is_valid = all(self.valid_sub[e] in disclosed_attributes for e in revealed_attributes)
        if not is_valid:
            print("ERR: The couples in the discole proof and in the ones stored on the server are not the same")
            return False

        # Check the signature
        Rnd_user = [v for k, v in Rnd_is if k == user_att_idx][0]
        s_user = [v for k, v in s_is if k == user_att_idx][0]

        c_pk = (sigp1 ** s_user) / (Rnd_user ** challenge)

        return sigp1.pair(client_signature) == c_pk.pair(G2.hash_to_point(message))
        
class Client:
    """Client"""

    def __init__(self, username:str = None, subs_list:List[str] = None):
        """
        Client constructor.
        """
        self.pk: c.PublicKey = None
        self.sk: c.SecretKey = None
        self.username: str = username
        self.subs_list: List[str] = subs_list
        
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
        # Deserialization
        server_pk = jsonpickle.decode(server_pk)
        (_, Y, _, _, _) = server_pk # Need the number of attributes to generate client's keys (length of Y)
        
        if self.username == None: 
            self.username = username
        
        if self.subs_list == None:
            self.subs_list = subscriptions
        else:
            self.subs_list = list(set(self.subs_list) | set(subscriptions))
        
        # Secret key of client
        (sk_c, pk_c) = c.generate_key(Y)
        self.pk = pk_c
        self.sk = sk_c
        
        # User attributes : client's secret key (with key 0)
        (x,_,_) = sk_c
        user_att = [(0, x)]
        
        # Create the request
        (req, t) = c.create_issue_request(server_pk, user_att)
        
        # Save t in the state
        state = t
        
        return (jsonpickle.encode(req).encode(), state)

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
        t = private_state
        
        # Deserialize server response, if None returns None
        server_pk = jsonpickle.decode(server_pk)
        response_dec = jsonpickle.decode(server_response)
        if response_dec == None:
            return jsonpickle.encode(None).encode()

        ((sigp1, sigp2), iss_att) = response_dec

        # Somehow the key of the attributes are cast to str -> recast to int
        iss_att = [(int(key), att) for (key, att) in iss_att]
        response_dec = ((sigp1, sigp2), iss_att)
                
        # Obtain credentials
        (x,_,_) = self.sk
        user_att = [(0, x)]
        user_att.extend(iss_att)

        credential = c.obtain_credential(server_pk, (sigp1, sigp2), t, user_att)
        return jsonpickle.encode(credential).encode() # Could be an encoded None
        
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
        
        server_pk = jsonpickle.decode(server_pk)
        
        credentials = jsonpickle.decode(credentials)
        if credentials == None:
            return jsonpickle.encode(None).encode()
        

        # TODO: check which one works, but both should
        # User attributes is the one with key 0
        (_, att) = credentials
        hidden_att = [(int(k), v) for k, v in att if int(k) == 0]
        _, x = hidden_att[0]
        # (x, _, _) = self.sk
        # hidden_att = [(0, x)]
        
        # Create discolsure proof using its credentials
        disc_proof = c.create_disclosure_proof(server_pk, credentials, hidden_att)
        
        # Sign the message using PS scheme
        # client_signature = c.sign(self.sk, [message])
        # if client_signature == None:
        #     return jsonpickle.encode(None).encode()
        client_signature = G2.hash_to_point(message) ** x
        
        return jsonpickle.encode((client_signature, disc_proof)).encode()
