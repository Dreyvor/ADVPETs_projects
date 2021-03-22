"""
Unit tests for expressions.
Testing expressions is not obligatory.

MODIFY THIS FILE.
"""

from expression import Secret, Scalar


# Example test, you can adapt it to your needs.
def test_expr_construction():
    a = Secret(1)
    b = Secret(2)
    c = Secret(3)
    expr = (a + b) * c * Scalar(4) + Scalar(3)
    assert repr(expr) == "((Secret(1) + Secret(2)) * Secret(3) * Scalar(4) + Scalar(3))"
    print("test_expr_constrution ok")

def test_mul_scalar():
    expr = Scalar(1)*Scalar(2)
    assert repr(expr) == "Scalar(1) * Scalar(2)"
    print("test_mul_scalar ok")

def test_sub_scalar():
    expr = Scalar(1)-Scalar(2)
    assert repr(expr) == "(Scalar(1) - Scalar(2))"
    print("test_sub_scalar ok")

def test_add_scalar():
    expr = Scalar(1)+Scalar(2)
    assert repr(expr) == "(Scalar(1) + Scalar(2))"
    print("test_add_scalar ok")

def test_new_scalar():
    expr = Scalar(0)
    assert repr(expr) == "Scalar(0)"
    print("test_new_scalar ok")

def test():
    test_new_scalar()
    test_add_scalar()
    test_sub_scalar()
    test_mul_scalar()
    test_expr_construction()
    
test()