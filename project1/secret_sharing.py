"""
Secret sharing scheme.
"""

from typing import List
import numpy as np

#from expression import Secret

#TODO: Modify this power for 64
q = 2**12 # global variable q

class Share:
    """
    A secret share in a finite field.
    """
    
    def __init__(self, value: int):
        self.value = value
        self.bn = str(value)
        
    def __repr__(self):
        # Helps with debugging.
        return f"{self.__class__.__name__}({self.value})"

    def __add__(self, other):
        return Share(self.value + other.value)

    def __sub__(self, other):
        return Share(self.value - other.value)

    def __mul__(self, other):
        return Share(self.value * other.value)


def share_secret(secret: int, num_shares: int) -> List[Share]: ############################ NOT TESTED YET
    """Generate secret shares."""
    np.random.seed()
    s = np.random.randint(0, high=q, size=num_shares)
    s[0] = (secret - np.sum(s) + s[0]) % q
    
    lShare = [Share(s_i) for s_i in s]
    return lShare
    

def reconstruct_secret(shares: List[Share]) -> int: ############################ NOT TESTED YET
    """Reconstruct the secret from shares."""
    res = Share(0)
    for s in shares:
        res += s
    return res.value % q
    


# Feel free to add as many methods as you want.
