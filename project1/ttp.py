"""
Trusted parameters generator.

MODIFY THIS FILE.
"""

import collections
from typing import (
    Dict,
    Set,
    Tuple,
    List,
)

from secret_sharing import (
    share_secret,
    Share,
    q, 
)

import random as rnd

# Feel free to add as many imports as you want.


class TrustedParamGenerator:
    """
    A trusted third party that generates random values for the Beaver triplet multiplication scheme.
    """

    def __init__(self):
        self.participant_ids: Set[str] = set()
        self.triplet_dict: Dict[Tuple[str, str], Tuple[Share, Share, Share]] = collections.defaultdict(dict)

    def add_participant(self, participant_id: str) -> None:
        """
        Add a participant.
        """
        self.participant_ids.add(participant_id)

    def generate_triplet(self, client_id: str, op_id: str) -> Tuple[Share, Share, Share]:
        """
        Generate a triplet for a given op_id and retrieve the share for the pair (client_id, op_id)
        """
        # Generate a triplet
        a = rnd.randint(0, q)
        b = rnd.randint(0, q)
        c = a * b % q

        # Split each value into multiples shares (each clients will have a share of a, b and c)
        nb_participants = len(self.participant_ids)
        a_shares : List[Share] = share_secret(a, nb_participants)
        b_shares : List[Share] = share_secret(b, nb_participants)
        c_shares : List[Share] = share_secret(c, nb_participants)

        # Store the shares in the ttp's dict
        for idx, p_id in enumerate(self.participant_ids):
            self.triplet_dict[(p_id, op_id)] = (a_shares[idx], b_shares[idx], c_shares[idx])

        res = self.triplet_dict.get((client_id, op_id))

        return res

    def retrieve_share(self, client_id: str, op_id: str) -> Tuple[Share, Share, Share]:
        """
        Retrieve a triplet of shares for a given client_id.
        """
        triplet = self.triplet_dict.get((client_id, op_id))
        if triplet == None:
            triplet = self.generate_triplet(client_id, op_id)
        return triplet

    # Feel free to add as many methods as you want.
