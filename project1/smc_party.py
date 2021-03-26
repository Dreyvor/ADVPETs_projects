"""
Implementation of an SMC client.

MODIFY THIS FILE.
"""
# You might want to import more classes if needed.

import collections
import json
from typing import (
    Dict,
    Set,
    Tuple,
    Union
)
from expression import Secret
from communication import Communication
from expression import (
    Expression,
    Secret, Scalar,
    AddOp, SubOp, MultOp
)
from protocol import ProtocolSpec
from secret_sharing import(
    reconstruct_secret,
    share_secret,
    Share,
)
import numpy as np
from typing import List

# Feel free to add as many imports as you want.


class SMCParty:
    """
    A client that executes an SMC protocol to collectively compute a value of an expression together
    with other clients.

    Attributes:
        client_id: Identifier of this client
        server_host: hostname of the server
        server_port: port of the server
        protocol_spec (ProtocolSpec): Protocol specification
        value_dict (dict): Dictionary assigning values to secrets belonging to this client.
    """

    def __init__(
            self,
            client_id: str,
            server_host: str,
            server_port: int,
            protocol_spec: ProtocolSpec,
            value_dict: Dict[Secret, int]
        ):
        self.comm = Communication(server_host, server_port, client_id)

        self.client_id = client_id
        self.protocol_spec = protocol_spec
        self.value_dict = value_dict
        self.private_shares: Dict[Secret, Share] = dict()

    def run(self) -> int:
        """
        The method the client use to do the SMC.
        """
        # Generate share
        num_shares = len(self.protocol_spec.participant_ids)
        for (secret,val) in self.value_dict.items():
            lShares = list(share_secret(val, num_shares)) # generate shares
            self.private_shares[secret] = lShares[0]
        
            # Send shares as private msg
            idx = 1
            for participant_id in [p_id for p_id in self.protocol_spec.participant_ids if p_id != self.client_id]:
                self.comm.send_private_message(participant_id, str(secret.getId()), str(lShares[idx].value))
                idx = idx + 1
        
        # Process expression
        res_process = self.process_expression(self.protocol_spec.expr)
            
        # Share, publish_msg
        labelFinal = 'computed_shares'
        self.comm.publish_message(labelFinal, str(res_process.value))
        
        # Retrieve and combine for final result
        parts_to_combine = []
        for participant_id in self.protocol_spec.participant_ids:
            # retrieve
            part_res = Share(int(self.comm.retrieve_public_message(participant_id, labelFinal)))
            parts_to_combine.append(part_res)
        # combine
        res = reconstruct_secret(parts_to_combine)

        return res

    # Suggestion: To process expressions, make use of the *visitor pattern* like so:
    def process_expression(
            self,
            expr: Expression
        ) -> Share:
        
        # if expr is an addition operation:
        if(isinstance(expr,AddOp)):
            return self.process_expression(expr.a) + self.process_expression(expr.b)
        
        # if expr is a substraction operation:
        if(isinstance(expr,SubOp)):
            return self.process_expression(expr.a) - self.process_expression(expr.b)

        # if expr is a multiplication operation:
        if(isinstance(expr,MultOp)):
            if(isinstance(expr.a,Scalar) and isinstance(expr.b,Scalar)):
                return self.process_expression(expr.a) * self.process_expression(expr.b)
            

        # if expr is a secret:
        if(isinstance(expr, Secret)):
            if(self.private_shares.get(expr) != None): #if the secret is its own
                #sec = self.value_dict.get(expr)
                sec = self.private_shares.get(expr).value
                assert(sec != None) # TODO: delete this
                return Share(sec) # return the value of the secret in a Share
            else:
                # get the share sent to you corresponding to the secret
                ret = self.comm.retrieve_private_message(str(expr.getId()))
                assert(ret != None) # TODO: delete this
                return Share(int(ret))
            
        # if expr is a scalar:
        if(isinstance(expr,Scalar)):
            # only the first participant adds the Scalar
            if(self.client_id == self.protocol_spec.participant_ids[0]):
                return Share(expr.value)
            else:
                return Share(0)
        
        # Call specialized methods for each expression type, and have these specialized
        # methods in turn call `process_expression` on their sub-expressions to process
        # further.
        pass

    # Feel free to add as many methods as you want.
