#!/usr/bin/env python3
from unicodedata import decimal
import util
from Cryptodome.PublicKey import RSA
from random import randint
from decimal import *
from functools import partial


class Param:
    def __init__(self, N, g, k):
        self.set_param(self, N, g, k)

    def set_param(self, N, g, k):
        self.N = N
        self.g = g
        self.k = k


class BCP:
    def __init__(self, secparam=1024, param=None) -> None:
        def g_finder(n2: decimal):
            for i in range(2, n2):
                if ((i ** (self.pp *self.qq)) % n2) % self.N == 1:
                    return i
        if param:
            self.N = param.N
            self.g = param.g
            self.k = param.k
            self.n2 = self.N * self.N
        else:
            RsaKey = RSA.generate(secparam)
            # self.pp is p', self.qq is q'
            self.pp = (RsaKey.p - 1) >> 1
            self.qq = (RsaKey.q - 1) >> 1
            self.N = RsaKey.n

            self.n2 = self.N * self.N

            # # E. Bresson, D. Catalano, and D. Pointcheval, “A simple public-key
            # # cryptosystem with a double trapdoor decryption mechanism and its
            # # applications, ” in Proc. ASIACRYPT, 2003, pp. 37–54.
            # mu = randint(1, self.n2)
            # self.g = (mu ** (self.N << 1) * -1) % self.n2
            # self.k = ((self.g ** (self.pp * self.qq) % self.n2) - 1) / self.N

            # $g ∈ \mathbb{Z}^{*}_{N^2}$
            # $g^{p' q'} mod N^2 = 1 + kN for k∈[1, N-1]$
            # Pick a pair of random number k and s
            self.k, s = randint(1, self.N), randint(0, self.N)
            # g = (((1+kN) + s(N^2)) ^ (1/(p'q'))) mod N^2
            # self.g = (1 + self.k * self.N + s * self.n2) ** (1 /
            #                                                  Decimal(self.pp * self.qq)) % self.n2
            self.g = g_finder(self.n2)

        self.key_renew()

    def set_param(self, param: Param) -> None:
        self.N = param.N
        self.g = param.g
        self.k = param.k

    def get_param(self) -> Param:
        return Param(self.N, self.g, self.k)

    def key_renew(self) -> None:
        '''
        Generate a new key from the self param
        '''
        # sk: secret key
        # pk: public key
        self.sk = randint(1, self.n2)
        self.pk = (self.g ** self.sk) % self.n2

    def key_gen(self) -> None:
        '''This is name aliasing of key_renew'''
        self.key_renew(self)

    def Encrypt(self, m: int) -> tuple():
        if (m > self.N):
            raise ValueError("m must smaller than {}".format(self.N))
        r = randint(1, self.n2)
        A = self.g * r % self.n2
        B = (self.pk ** r) * (1 + m * self.N) % self.n2
        return A, B

    def Decrypt(self, A: int, B: int) -> int:
        # print(B / (A ** self.sk))
        return ((B / (A ** self.sk) - 1) % self.n2) / self.N

    def mDecrypt(self, A: int, B: int) -> int:
        k_inv = util.mod_inv(self.k, self.N)
        a = (((self.pk ** (self.pp * self.qq) - 1) %
             self.n2) / self.N * k_inv) % self.N
        r = (((A ** (self.pp * self.qq) - 1) %
              self.n2) / self.N * k_inv) % self.N
        delta = util.mod_inv(self.pp * self.qq, self.N)
        gamma = a * r % self.N
        return (((B/(self.g ** gamma)) ** (self.pp * self.qq) - 1) % self.n2) / self.N * delta % self.N

    def subprotocol(self, func):
        setattr(self, func.__name__, partial(func, self))
        return func


if __name__ == '__main__':
    p = BCP()

    @p.subprotocol
    def show(self):
        print("p'", self.pp)
        print("q'", self.qq)
        print("g", self.g)
        print("k", self.k)
        print("sk", self.sk)
        print("pk", self.pk)

    p.show()

    t = p.Encrypt(213)
    print(t)
    print(p.Decrypt(*t))
