import sys
sys.path.append("..")
import ecc
from ecc import PrivateKey
from random import randint
import helper
from helper import little_endian_to_int, double_sha256, sha256

# hash
def H(*args):
    return double_sha256(b''.join(args))

# int(hash)
def HI(*args):
    return little_endian_to_int(H(*args))

def gen_msg():
    return randint(0, 2**256).to_bytes(256//8, 'little')

class schnorr():

    def __init__(self, secret):
      self.secret = secret;
      self.privatekey = PrivateKey(self.secret)
      self.point = self.privatekey.point # public point

    def sign(self, msg):
        k = randint(0, 2**256) # nonce
        R = k * ecc.G          # nonce point
        s = (k + HI(R.sec(), msg) * self.secret)%ecc.N
        return R, s

    def verify(self, R, s, msg):
        Q = s * ecc.G - HI(R.sec(),msg) * self.point
        return Q

    #z = gen_msg()
    #R, s = sign(pk, z)
    #assert verify(R, s, z)

def BN(Ns=10): # num sig
    pks = [PrivateKey(randint(0, 2**256)) for _ in range(Ns)]
    points = [pk.point for pk in pks]

    def sign(pks, z):
        ks = [randint(0, 2**256) for _ in range(len(pks))]

        L = H(*[p.sec() for p in points])
        Rs = [k*ecc.G for k in ks]
        R = sum(Rs, ecc.S256Point(None,None))
        cs = [HI(L,p.sec(),R.sec(),z) for p in points]
        s = sum(k + c*pk.secret for k,c,pk in zip(ks,cs,pks))%ecc.N
        return R, s

    def verify(R, s, z):
        L = H(*[p.sec() for p in points])
        cs = [HI(L,p.sec(),R.sec(),z) for p in points]
        return R == s*ecc.G - sum((c*p for c,p in zip(cs, points)),ecc.S256Point(None,None))

    z = gen_msg()
    R, s = sign(pks, z)
    assert verify(R, s, z)

def Mu(Ns=10):
    pks = [PrivateKey(randint(0, 2**256)) for _ in range(Ns)]
    points = [pk.point for pk in pks]

    def sign(pks, z):
        L = H(*[p.sec() for p in points])
        ks = [randint(0, 2**256) for _ in range(len(pks))]
        Rs = [k*ecc.G for k in ks]
        R = sum(Rs, ecc.S256Point(None,None))
        # aggregate key
        P = sum((HI(L, p.sec())*p for p in points), ecc.S256Point(None,None))
        cs = [HI(R.sec(),z)*HI(L,p.sec()) for p in points]
        s = sum([k+c*pk.secret for k,c,pk in zip(ks,cs,pks)]) % ecc.N
        return R, s, P

    def verify(R, s, z, P):
        return R == s*ecc.G - HI(R.sec(),z)*P

    z = gen_msg()
    R, s, P = sign(pks, z)
    assert verify(R, s, z, P)

#funcs = [schnorr, BN, Mu]
#[f() for f in funcs]
