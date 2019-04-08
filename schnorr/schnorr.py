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
        Q = (s * ecc.G) - (HI(R.sec(),msg) * self.point)
        return Q == R


class BN(): # num sig
    
    def __init__(self, private_keys):
        self.pks = []
        for i in range(len(private_keys)):
            secret = little_endian_to_int(double_sha256(private_keys[i]))
            self.pks.append(PrivateKey(secret=secret))
        self.points = [pk.point for pk in self.pks]

    def sign(self, msg):
        ks = [randint(0, 2**256) for _ in range(len(self.pks))]

        L = H(*[p.sec() for p in self.points])
        Rs = [k*ecc.G for k in ks]
        R = sum(Rs, ecc.S256Point(None,None))
        cs = [HI(L,p.sec(),R.sec(),msg) for p in self.points]
        s = sum(k + c*pk.secret for k,c,pk in zip(ks,cs,self.pks))%ecc.N
        return R, s

    def verify(self, R, s, msg):
        L = H(*[p.sec() for p in self.points])
        cs = [HI(L,p.sec(),R.sec(),msg) for p in self.points]
        return R == s*ecc.G - sum((c*p for c,p in zip(cs, self.points)),ecc.S256Point(None,None))



class Mu():
    
    def __init__(self, private_keys):
        self.pks = []
        for i in range(len(private_keys)):
            secret = little_endian_to_int(double_sha256(private_keys[i]))
            self.pks.append(PrivateKey(secret=secret))
        self.points = [pk.point for pk in self.pks]

    def sign(self, msg):
        L = H(*[p.sec() for p in self.points])
        ks = [randint(0, 2**256) for _ in range(len(self.pks))]
        Rs = [k*ecc.G for k in ks]
        R = sum(Rs, ecc.S256Point(None,None))
        # aggregate key
        P = sum((HI(L, p.sec())*p for p in self.points), ecc.S256Point(None,None))
        cs = [HI(R.sec(),msg)*HI(L,p.sec()) for p in self.points]
        s = sum([k+c*pk.secret for k,c,pk in zip(ks,cs,self.pks)]) % ecc.N
        return R, s, P

    def verify(self, R, s, msg, P):
        return R == s*ecc.G - HI(R.sec(),msg)*P
