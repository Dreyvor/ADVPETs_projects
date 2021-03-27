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

from ttp import TrustedParamGenerator

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
            expr: Expression,
            curr_in_mult=False # Check if we are currently in a mult
        ) -> Share:
        
        # if expr is an addition operation:
        if(isinstance(expr, AddOp)):
            return self.process_expression(expr.a) + self.process_expression(expr.b)
        
        # if expr is a substraction operation:
        if(isinstance(expr, SubOp)):
            return self.process_expression(expr.a) - self.process_expression(expr.b)

        # if expr is a multiplication operation:
        #TODO: Check/test the mult part
        if(isinstance(expr, MultOp)):
            # We use triplets beavers only if there is a secret in each operand.
            # Let's check that
            if self.contains_secret(expr.a) and self.contains_secret(expr.b):
                x = self.process_expression(expr.a, True)
                y = self.process_expression(expr.b, True)

                x_min_a, y_min_b, c = self.gen_beavers_shares(x, y, expr)

                # Only add the constant once in the computation
                if self.client_id == self.protocol_spec.participant_ids[0]:
                    return c + x * y_min_b + y * x_min_a - x_min_a * y_min_b
                else:
                    return c + x * y_min_b + y * x_min_a
            
            else:
                print("X"*30, "mult but not two secrets")
                t1 = self.process_expression(expr.a, True)
                t2 = self.process_expression(expr.b, True)
                print("X"*30, t1, "mult", t2)
                return t1 * t2

        # if expr is a secret:
        if(isinstance(expr, Secret)):
            sec = self.private_shares.get(expr) #TODO: work with expr.getId instead of expr ?
            if(sec != None): #if the secret is its own
                return Share(sec.value) # return the value of the secret in a Share
            else:
                # get the share sent to you corresponding to the secret
                sec = self.comm.retrieve_private_message(expr.getId())
                assert(sec != None) # TODO: delete this
                return Share(int(sec))
            
        # if expr is a scalar:
        if(isinstance(expr,Scalar)):
            # only the first participant adds the Scalar
            if(self.client_id == self.protocol_spec.participant_ids[0]) or curr_in_mult:
                return Share(expr.value)
            else:
                return Share(0)
        
        # Call specialized methods for each expression type, and have these specialized
        # methods in turn call `process_expression` on their sub-expressions to process
        # further.
        pass

    # Recursive search checking if an expr contains a secret
    def contains_secret(
            self,
            expr : Expression
        ):
        if isinstance(expr, Secret):
            return True
        elif isinstance(expr, Scalar):
            return False
        else:
            return self.contains_secret(expr.a) or self.contains_secret(expr.b)

    # Generate x-a, y-b and c using beavers
    def gen_beavers_shares(
            self, 
            x : Share, 
            y : Share, 
            expr : Expression
        ) -> Tuple[Share, Share, Share]:

        # messages label for public msg will be: "self.client_id + op_id + _x_min_a"

        op_id = expr.getId()

        a, b, c = self.comm.retrieve_beaver_triplet_shares(op_id)

        # Compute x-a and y-b and send shares to others publicly
        # TODO: check if the shares should be public or private
        x_min_a_share = x - Share(a)
        y_min_b_share = y - Share(b)

        self.comm.publish_message(self.client_id + op_id + "_x_min_a", str(x_min_a_share.value))
        self.comm.publish_message(self.client_id + op_id + "_y_min_b", str(y_min_b_share.value))

        rebuilt_x_min_a_share = x_min_a_share
        rebuilt_y_min_b_share = y_min_b_share

        # Reconstruct x-a and y-b with the shares of others
        for p_id in [p_id for p_id in self.protocol_spec.participant_ids if p_id != self.client_id]:
            other_x = None
            other_y = None

            # Wait on others to upload their shares
            while(other_x is None):
                other_x = self.comm.retrieve_public_message(p_id, p_id + op_id + "_x_min_a")
            
            while(other_y is None):
                other_y = self.comm.retrieve_public_message(p_id, p_id + op_id + "_y_min_b")

            rebuilt_x_min_a_share += other_x
            rebuilt_y_min_b_share += other_y

        return rebuilt_x_min_a_share, rebuilt_y_min_b_share, c

