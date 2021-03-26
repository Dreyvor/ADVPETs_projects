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
        self.private_shares = List[Share]

    def run(self) -> int:
        """
        The method the client use to do the SMC.
        """
        # Generate share
        shares_per_secret = Dict[Secret,List[Share]]
        
        num_shares = len(self.protocol_spec.participant_ids)
        for (secret,val) in self.value_dict:
            lShares = share_secret(val,num_shares) # generate shares
            shares_per_secret[secret] = lShares
        
            # Send shares as private msg
            idx = 0
            for participant_id in self.protocol_spec.participant_ids:
                self.comm.send_private_message(participant_id, secret.getId(), str(shares_per_secret[secret][idx]))
                idx = idx + 1
        
        # Process expression
        res_process = self.process_expression(self.protocol_spec.expr)
            
        # Share, publish_msg
        labelFinal = 'computed_shares'
        self.comm.publish_message(labelFinal,str(res_process))
        
        # Retrieve and combine for final result
        res = Share(0)
        for participant_id in self.protocol_spec.participant_ids:
            part_res = Share(self.comm.retrieve_public_message(participant_id,labelFinal)) # retrieve
            res += part_res # combine
        
        return res.getValue()

    # Suggestion: To process expressions, make use of the *visitor pattern* like so:
    def process_expression(
            self,
            expr: Expression
        ) -> Share:
        
        # if expr is an addition operation:
        if(isinstance(expr,AddOp)):
            self.process_expression(expr) + self.process_expression(expr)

        # if expr is a multiplication operation:
        if(isinstance(expr,MultOp)):
            self.process_expression(expr) * self.process_expression(expr)

        # if expr is a secret:
        if(isinstance(expr,Secret)):
            raise NotImplementedError("How should we treat secrets ?") 
            
        # if expr is a scalar:
        if(isinstance(expr,Scalar)):
            raise NotImplementedError("How should can we eval to obtain the value in Scalar (getter in Expression ??) ?")
        
        # Call specialized methods for each expression type, and have these specialized
        # methods in turn call `process_expression` on their sub-expressions to process
        # further.
        pass

    # Feel free to add as many methods as you want.
