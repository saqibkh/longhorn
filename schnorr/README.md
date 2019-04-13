Schnorr Signatures

-> Easier scheme than ECDSA.

-> Uses hashes instead of division.

-> Allows for signature aggregation using Bellare-Naven.

-> Allows for Pubkey aggregation using MuSig.

-> Demo: Sign a message we give you using a 3-of-3 MuSig aggregate key.

------------------------------------------------------------------------------------------------------------------------------------
------------------------------------------------------------------------------------------------------------------------------------
Schnorr:  

    Instead of field division, we use hashes.
    
    Signing: 
        Given a secret P=eG, select random number k
        R = kG, s = k + Hash(R||z)e
        Signature is (R,s)
    
    Verification:
            Given signature (R,s) and message (z) and public key (P)
            Q = sG - Hash(R||z)P
            if Q is the same as R, signature is valid
            
Bellare-Neven(BN):

    Generalize schnorr for multiple keys.
    Aggregates signatures.    
    In bitcoin currently, each signature has to be send seperately, so you have seperate (R,s) for every single pubkey. 
    We can aggregate and have a single (R,s)
        
    Signature:
        Pi = ei*G
        L = Hash(P1 || P2 || ... || Pn)
        Ri = ki*G
        R = R1 + R2 + .... Rn
        ci = Hash(L||Pi||R||z)
        si = ki | ciei
        s = s1 + s2 + ... + sn
        Signature (R,s)
        
    Verification:
        Given a signature(R,s), a message(z), and keys P1, P2, ...., Pn
        L = Hash (P1 || P2 || ... || Pn)
        ci = Hash (L || Pi || R || z),       where i=1,2,...,n
        sG - c1P1 - c2P2 - ... - cnPn == R means sig is valid
