"""
Secret sharing scheme.
"""

from typing import List
import numpy as np

#from expression import Secret

q = 2**20 # global variable q
# 2^20 : 1st power of 2 above 10^6

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
        return Share((self.value + other.value) % q)

    def __sub__(self, other):
        return Share((self.value - other.value) % q)

    def __mul__(self, other):
        return Share((self.value * other.value) % q)


def share_secret(secret: int, num_shares: int) -> List[Share]:
    """Generate secret shares."""
    np.random.seed()
    s = np.random.randint(0, high=q, size=num_shares)
    s[0] = (secret - np.sum(s) + s[0]) % q
    
    lShare = [Share(s_i) for s_i in s]
    return lShare
    

def reconstruct_secret(shares: List[Share]) -> int: 
    """Reconstruct the secret from shares."""
    res = Share(0)
    for s in shares:
        res += s
    return res.value % q
    


# Feel free to add as many methods as you want.
