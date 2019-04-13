Schnorr Signatures

-> Easier scheme than ECDSA.

-> Uses hashes instead of division.

-> Allows for signature aggregation using Bellare-Naven.

-> Allows for Pubkey aggregation using MuSig.

-> Demo: Sign a message we give you using a 3-of-3 MuSig aggregate key.

------------------------------------------------------------------------------------------------------------------------------------
------------------------------------------------------------------------------------------------------------------------------------
Schnorr: 
    
    Given signature (R,s) and message (z) and public key (P)
    Q = sG - Hash(R||z)P
    
    
    Signing: Given a secret P=eG, select random number k
    R = kG, s = k + Hash(R||z)e
    Signature is (R,s)
    
    Verification:
