# [__leakeyd__](#[leakeyd])

### Description:
* We managed to capture one of the enemy spies and get their keypair! It seems that each spy uses a different exponent though, can you still read their messages?

### Objective:
* common modulus attack on RSA

### Difficulty:
* `Easy`

### Flag:
* `HTB{tw4s_4-b3d_1d34_t0_us3-th4t_m0dulu5_4g41n-w45nt_1t...}`

### Release:
* [/release/crypto_leakeyd.zip](release/crypto_leakeyd.zip) (`fdfbd05ef8385e292333e6c82e1a94150f7d9b30956c362d002541320a4be4f7`)

### Challenge:

```python
from Crypto.Util.number import getPrime, bytes_to_long
from math import gcd

flag = open("flag.txt").read().strip().encode()

p = getPrime(1024)
q = getPrime(1024)
n = p * q
e1 = 0x10001
e2 = 0x13369


assert gcd(p-1,e1) == 1 and gcd(q-1, e1) == 1 and gcd(p-1,e2) == 1 and gcd(q-1, e2) == 1

phi = (p-1) * (q-1)
d1 = pow(e1, -1, phi)
print(f"""Retrieved agent data:
n = {n}
e = {e1}
d = {d1}""")

ct = pow(bytes_to_long(flag), e2, n)
print(f"""Spy messages: 
e = {e2}
ct = {ct}""")
```

Looking at `script.py`, we see that the code

- generates a random modulus
- generates the private key for the public key with exponent 0x10001
- encrypts the flag using the same modulus, but exponent 0x13369

Let's recap on how RSA keys are generated.

We generate a modulus `n` by multiplying primes `p` and `q`.

We then choose a random `e`, ensuring that it is coprime to the totient of `n`, in other words, ensuring that `p-1` and `q-1` don't share any factors with `e`, aside from 1.

Then, we can generate our private key by finding the inverse of `e` mod tot(n).

The `d` will satisfy the equation: e * d = 1 mod tot.

Knowing this, given `e` and `d`, how will we work out a private key for a different exponent?

Well, we know that `e * d = 1 mod tot`, and to generate a private key, we just need to know `e` and `tot`. 

We can work out a multiple of tot by doing `k * tot = (e * d) - 1`. Now, can we use this to work out `d`? 

Since we have `e * d = 1 mod k * tot`, and since `tot` is a multiple of `k * tot`, `e * d mod k * tot` is equivalent to `e * d mod tot`. This means that we can simply work out `d` by taking the inverse of `e` mod `k * tot`.

All that's left is to decrypt the message as usual by raising our ciphertext to the power of `d` and taking mod `n`


### Solver:

```python
from Crypto.Util.number import long_to_bytes

data = open("output.txt").read().split("\n")
n = int(data[1].split(" ")[-1])
e1 = int(data[2].split(" ")[-1])
d1 = int(data[3].split(" ")[-1])
e2 = int(data[5].split(" ")[-1])
ct = int(data[6].split(" ")[-1])

# e * d = 1 mod tot(n)
# any multiple of tot(n) will work when calculating the private exponent
# therefore we put tot as e * d - 1

tot = e1 * d1 - 1
d2 = pow(e2,-1,tot)
pt = pow(ct, d2, n)
print(f"Flag: {long_to_bytes(pt).decode()}")
```
