Basic Kerberos _mock_.  

P.S. This is a basic demo for a school assignment and clearly, I don't know much about security, if at all. In this project, there is no concept of networking, and _machines_ are Python objects.

# Run
Requires Python 3.10+  

```bash
cd kerberos-demo
# python -m venv venv
# source ./venv/bin/activate
pip install -r requirements.txt
python main.py
```
# TODO
Add tests

# Kerberos
## client authentication
client sends to KDC{AS}:  
    1. (nameA)  

KDC finds nameA in DB  
KDC replies with:  
    1. tC {( skAK, exp1 )}kA  
    2. TGT {(skAK, exp1, nameA)}kK  

client decrypts tC using own kA -> saves skAK and TGT { save exp }  

## client service authorization
client sends to KDC{TGS}:  
    1. (TGT, nameB)  
    2. authenticator {(nameA, timestamp)}skAK  

TGS decrypts TGT(skAK, exp, nameA); verifies exp  
TGS decrypts authenticator (nameA, timestamp) using skAK; verifies nameA==nameA*  
TGS replies with: ***  
    1. tS {( nameA, exp, skAB )}kB  
    2. {skAB}skAK  

client decrypts {skAB} with skAK to retrieve skAB  

## client service request
client sends to B:  
    1. tS #{( nameA, exp, skAB )}kB  
    2. authenticator {(nameA, timestamp3)}skAB  

B decrypts tS( nameA, exp, skAB ) using kB, retrieves skAB; verifies exp  
B decrypts authenticator using skAB; verifies nameA==nameA  
server sends to A:  
    1. {timestamp3+1}skAB  
client descrypts {timestamp3+1} using skAB, verifies timestamp is correct  


A - client  
B - service  
AS - authentication service  
TGS - ticket granting service  
sk - session key  
tC - client ticket  
#{} - opaque response  
