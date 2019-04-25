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
        Given a secret "e", P = e * G , where "P" is the public key and "G" is the generator point. 
        Select a random number k
        R = kG, s = k + Hash(R||z)e
        Signature is (R,s)  (R is the random value and s is the signature)
    
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
        Pi = ei*G         (Pi = public key for ith element) (ei is the secret for ith element)
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
        
   MuSig
   
    Aggregates not just the signature (R,s) but also the Public Keys (P)
    So, instead of sending multiple public keys for verification, we send one aggregate Public Key (P)
    
    As far as the verifier is concerned a verifier doesn't know if its a single private key or multiple private keys that generated the signature
    
    Signature:
        Pi = ei*G         (Pi = public key for ith element) (ei is the secret for ith element)
        L = Hash(P1 || P2 || ... || Pn)        Ri = ki*G
        R = R1 + R2 + .... Rn
        P = H(L||P1)P1 + H(L||P2)P2 ..... + H(L||Pn)Pn
        ci = Hash(L||Pi||R||z)
        si = ki | ciei
        s = s1 + s2 + ... + sn
        Signature (R,s)   Public-Key (P)
    
    Verification:
        Given a signature(R,s), a message(z), and public-key (P)
        L = Hash (P1 || P2 || ... || Pn)
        ci = Hash (L || Pi || R || z),       where i=1,2,...,n
        sG - c1P1 - c2P2 - ... - cnPn == R means sig is valid
