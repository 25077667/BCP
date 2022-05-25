#!/usr/bin/env python3
from sys import version_info


def egcd(a, b):
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = egcd(b % a, a)
        return (g, x - (b // a) * y, y)


def mod_inv(a: int, m: int):
    # if version is greater than 3.8, use the builtin function
    if version_info.major << 8 + version_info.minor > 3 << 8 + 8:
        return pow(a, -1, m)
    g, x, y = egcd(a, m)
    if g != 1:
        raise Exception('modular inverse does not exist')
    else:
        return x % m
