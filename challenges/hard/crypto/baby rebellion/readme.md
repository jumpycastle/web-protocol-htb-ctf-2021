#  [Baby Rebellion](#baby_rebellion)
![category](https://img.shields.io/badge/category-crypto-red)

![](https://i.imgur.com/XsJa66K.png)

### [__Description__](#description)
* A shady organization has been developing cyborgs, with a plan for world-domination. They have set up a lab where they insert microchips inside test subjects in order to start the cyborg transition. Our team of IT experts has hacked one of the organizations' mail servers. There is a suspicious encrypted mail which possibly contains information related to the location of the lab. Your mission, if you choose to accept it, is to decrypt the message and find the coordinates of the lab.

### [__Objective__](#objective)
* Players are provided with 4 `.crt` files and a `challenge` file which is a **s/mime** file of a **pkcs#7 enveloped-data** object.
* They need to perform Hastad's Broadcast Attack on RSA to retrieve an **AES key** which is used for the encryption of the actual message.
* Players have to familiarize themselves with several [RFCs](https://en.wikipedia.org/wiki/Request_for_Comments) in order to solve this challenge, namely [2633](https://tools.ietf.org/html/rfc2633),  [2315](https://tools.ietf.org/html/rfc2315#section-6.2), [2313](https://tools.ietf.org/html/rfc2313).
### [__Difficulty__](#difficulty)
* `hard`
### [__Flag__](#flag)
* `HTB{37.220464, -115.835938}`

### [__Downloadables__](#downloadables)
* `.crt` files: certificates of recipients.
* A file containing the encrypted message.

### [__Challenge__](#challenge)
To prepare this challenge, the steps below were followed:
* Generate a pair of keys for each recipient. For the purpose of this challenge `e = 3` . Remember that the number of messages should be equal or greater than the value of `e`. Otherwise, the attack is not feasible.

`openssl genrsa -3 -out <OUTPUT> <BITS> -pubout`

* Create a self-signed certificate from each key pair.

`openssl req -new -x509 -nodes -days 365 -out <OUTPUT> -key <KEY>`

The certificates are used for [email encryption](https://en.wikipedia.org/wiki/Email_encryption) in real life and this is why they are needed.

#### [__Encryption of data__](#encryption)
An **AES key** is generated with a **random IV** and are both used under `aes-cbc-256` to encrypt the original message containing the flag. Next, the public keys from the `.crt` files encrypt the `AES key` and all this information along with the encrypted message are contained in the `challenge` file.

This is a practical implementation of RSA in real life. The challenge implementation requires to go through several steps like encrypting an  _ascii message_,  making sure it is of length less than the modulus, choosing a big enough modulus, etc...

Textbook RSA is also  **deterministic** and thus it is **not semantically secure** , it is **malleable**.

Thus, to counter those in practice, RSA Encryption uses **padding** (usually [OAEP](https://en.wikipedia.org/wiki/Optimal_asymmetric_encryption_padding)) to make it **probabilistic** and **not malleable**.

In order to encrypt the data, [smime](https://github.com/balena/python-smime) module of Python has been used and modified. More specifically the `pubkey.py` script has been changed to add `\ff` as padding in the AES key before encryption. The padding is consisted of random bytes, originally.

This is the modified script performing the RSA encryption, where `session key` represents the **AES key**:
```python
from __future__ import unicode_literals
from abc import ABCMeta, abstractmethod
import os

fixed_random = b'\xff' * 512

class PublicKeyCipher(object):
    __metaclass__ = ABCMeta

    algo = None

    @abstractmethod
    def encrypt(self, session_key):
        return NotImplemented

    @property
    def parameters(self):
        return NotImplemented

class RSAPublicKeyCipher(PublicKeyCipher):
    algo = 'rsa'

    def __init__(self, public_key_info):
        rsaparams = public_key_info['public_key'].native
        self.e = rsaparams['public_exponent']
        self.n = rsaparams['modulus']
        self.size = (self.n.bit_length() + 7) // 8

    def pad(self, data):
        assert len(data) <= self.size - 3
        return b'\x00\x01' + fixed_random[:self.size-3-len(data)] + b'\x00' + data

    def encrypt(self, session_key):
        m = int.from_bytes(self.pad(session_key), 'big')
        return int.to_bytes(pow(m, self.e, self.n), self.size, 'big')

    @property
    def parameters(self):
        # AlgorithmIdentifier parameters is always NULL
        return None
```
#### [__Steps of Exploitation__](#exploitation)
Challenges should extract the ciphertexts from the `.msg` files and their respective public keys from the `.crt` files. 

##### [__Reading the data in the file__](#read_data)
Open the `challenge` file:
![](https://i.imgur.com/Ed6CuBN.png)

To read that we need to extract the pkcs7 object and parse it. OpenSSL allows us to do this:
```bash
openssl smime -in challenge -pk7out -out challenge.p7m
openssl asn1parse -in challenge.p7m
```
The output shows a dump of info to read. We care for the three parts which look like this:
![](https://i.imgur.com/kPKX1dy.png)

Which means the same message was sent to three recipients, identified by their serial number which we recognize as being our Mechi, Corius and Andromeda.

The end of the output is really important as well:
![](https://i.imgur.com/MNoLNzq.png)

Which means that the data sent (after this dump) is encrypted by AES in CBC mode with an IV `78BD3D7556BB10FFF1E3AFF4A31BD64A`.

##### [__Quick reminder on CBC mode__](#cbc)
**[CBC](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Cipher-block_chaining_.28CBC.29)** is a mode of operation. A block cipher can only encrypt/decrypt blocks of a certain size. 
![](https://i.imgur.com/rqoCSGt.png)

##### [__Hastad's Broadcast Attack - What is it and why does it work?__](#hastad)
Dr Greez sent an encrypted message _M_ to a number of cyborgs CB<sub>1</sub>, CB<sub>2</sub>, ..., CB<sub>k</sub>. Each cyborg has its own RSA key (N<sub>i</sub>, e<sub>i</sub>). We assume _M_ is less than all the N<sub>i</sub>'s. To send M, Dr Greez encrypts it using each of the public keys and sends out of the _i_-th ciphertext to CB<sub>i</sub>. Challengers are provided with _k_ transmitted ciphertexts.

For simplicity, suppose all public exponents e<sub>i</sub>, are equal to 3. A simple arguments shows that players can recover _M_ if _k_ ≥ 3. Indeed, Bob obtains C<sub>1</sub>, C<sub>2</sub>, C<sub>3</sub>, where
C<sub>1</sub> = M<sup>3</sup> mod N<sub>1</sub>,
C<sub>2</sub> = M<sup>3</sup> mod N<sub>2</sub>,
C<sub>3</sub> = M<sup>3</sup> mod N<sub>3</sub>.

Assume that gcd(N<sub>i</sub>, N<sub>j</sub>) = 1 for all `i # j`since otherwise challengers can factor some of the N<sub>i</sub>'s. Hence, applying the [Chinese Remainder Theorem (CRT)](https://en.wikipedia.org/wiki/Chinese_remainder_theorem) to C<sub>1</sub>, C<sub>2</sub>, C<sub>3</sub> gives a C',  satisfying C' = M<sup>3</sup> mod N<sub>1</sub> N<sub>2</sub> N<sub>3</sub>. Since M is less than all the N<sub>i</sub>'s, we have M<sup>3</sup>< N<sub>1</sub> N<sub>2</sub> N<sub>3</sub>. Then C' = M<sup>3</sup> holds over the integers. Thus, someone may recover M by computing the real cube root of C'. More generally, if all public exponents are equal to `e`, players can recover _M_ as soon as _k_ > _e_. The attack is feasible only when a small `e` is used.

##### [__AES decryption__](#aes-decryption)
Converting the resulted number in **hex** yields the following string:
![](https://i.imgur.com/itenOF8.png)

Based on [RFC 2323](https://tools.ietf.org/html/rfc2313),  A block type BT, a padding string PS, and the data D shall be formatted into an octet string EB, the encryption block.
```python
EB = 00  || BT || PS ||  00  || D .
```
The block type BT shall be a single octet indicating the structure of the encryption block. For this version of the document it shall have value 00, 01, or 02. For a private- key operation, the block type shall be 00 or 01. For a public-key operation, it shall be 02.

The padding string PS shall consist of k-3-||D|| octets. For block type 00, the octets shall have value 00; for block type 01, they shall have value FF; and for block type 02, they shall be pseudo-randomly generated and nonzero. This makes the length of the encryption block EB equal to k.

We have our **AES key**: `78BD3D7556BB10FFF1E3AFF4A31BD64A` to use.

Right now the ciphertext must be extracted to perform decryption. Players should remember the structure of the **s/mime** files.
pkcs7-envelopedData:
 - set of recipients:
	 - recipient info
	 -  certificate serial number
	 -  padded AES key encrypted with recipient's public key
- pkcs7-data:
	- block cipher info (aes-256-cbc)
	- plaintext IV
	- encrypted message

For that purpose someone could use [this](https://8gwifi.org/PemParserFunctions.jsp?fbclid=IwAR2hKq1gGgWpdaImBJis3e3YemO6RYXsvXEIwiNSaU4mjfioIBWdarh2YOc) or implement his/hers own script like the one provided below:
```python
import asn1, sys
from base64 import b64decode, b64encode

with open('downloadables/challenge', 'r') as f:
	while f.readline() != '\n':
		pass
	data = b64decode(f.read())
	
def class_id_to_string(cls):
	if cls == asn1.Classes.Universal:
		return 'U'
	if cls == asn1.Classes.Private:
		return 'P'
	return cls
	
TAGS = {}
for x in asn1.Numbers.__members__:
	TAGS[asn1.Numbers[x].value] = x
	
def tag_id_to_string(tag):
	return TAGS.get(tag, tag)
		
def value_to_string(tag, value):
	return value
	
def pretty_print(input_stream, output_stream, indent=0):
	while not input_stream.eof():
		tag = input_stream.peek()
		if tag.typ == asn1.Types.Primitive:
			tag, value = input_stream.read()
			output_stream.write(' ' * indent)
			output_stream.write('[{}] {}: {}\n'.format(class_id_to_string(tag.cls),
					  tag_id_to_string(tag.nr), value_to_string(tag.nr, value)))
		elif tag.typ == asn1.Types.Constructed:
			output_stream.write(' ' * indent)
			output_stream.write('[{}] {}\n'.format(class_id_to_string(tag.cls),
					  tag_id_to_string(tag.nr)))
			input_stream.enter()
			pretty_print(input_stream, output_stream, indent + 2)
			input_stream.leave()	
				
writer = asn1.Encoder()
writer.start()

reader = asn1.Decoder()
reader.start(data)

pretty_print(reader, sys.__stdout__)
```

The ciphertext of the outcome should look this:
![](https://i.imgur.com/JtRx3Zt.png)

### [__Solver__](solver)
```python
import os, sys, io, re, subprocess
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from Crypto.Util.number import long_to_bytes, bytes_to_long
from base64 import b64decode
from functools import reduce
from itertools import permutations

def mul_inv(a, b):
	b0 = b
	x0, x1 = 0, 1
	if b == 1: return 1
	while a > 1:
		q = a // b
		a, b = b, a%b
		x0, x1 = x1 - q * x0, x0
	if x1 < 0: x1 += b0
	return x1

def find_invpow(x,n):
	high = 1
	while high ** n < x:
		high *= 2
	low = high//2
	while low < high:
		mid = (low + high) // 2
		if low < mid and mid**n < x:
			low = mid
		elif high > mid and mid**n > x:
			high = mid
		else:
			return mid
	return mid + 1

def chinese_remainder(n, a):
	sum = 0
	prod = reduce(lambda a, b: a*b, n)

	for n_i, a_i in zip(n, a):
		p = prod // n_i
		sum += a_i * mul_inv(p, n_i) * p
	return sum % prod

def get_n(filename):
	with open(filename, 'r') as f:
		key = RSA.import_key(f.read())
		assert key.e == 3
		return key.n

e = 3

n0 = get_n('downloadables/mechi.crt')
n1 = get_n('downloadables/corius.crt')
n2 = get_n('downloadables/andromeda.crt')

data = []

with io.StringIO(subprocess.getoutput('openssl smime -in downloadables/challenge -pk7out | openssl asn1parse')) as x:
	for line in x.readlines():
		pos = line.find('[HEX DUMP]:')
		if pos > 0:
			data.append(bytes.fromhex(line[pos+11:]))
		else:
			m = re.match(r'^\s*(\d+):\s*d=\s*(\d+)\s+hl=\s*(\d+)\s+l=\s*(\d+)\s+prim:\s+cont', line)
			if m:
				offset, d, hl, l = int(m.group(1)), int(m.group(2)), int(m.group(3)), int(m.group(4))
				ciphertext = b64decode(subprocess.getoutput('openssl smime -in downloadables/challenge -pk7out')[len('-----BEGIN PKCS7-----')+1:-len('-----END PKCS7-----')-1])[offset+hl:offset+hl+l]


assert len(data) == 4, 'invalid number of blobs'
c0 = bytes_to_long(data[0])
c1 = bytes_to_long(data[1])
c2 = bytes_to_long(data[2])
aes_iv = data[3]

for moduli in permutations([n0, n1, n2]):
	result = chinese_remainder(moduli, [c0, c1, c2])
	result = find_invpow(result, 3)
	result = long_to_bytes(int(result))
	break
else:
	print('nothing worked :(')
	exit(1)

print(result)

assert result[0] == 1 and result[-33] == 0, 'not a valid PKCS#1 v1.5 encoding'
aes_key = result[-32:]

aes = AES.new(aes_key, AES.MODE_CBC, aes_iv)
print(unpad(aes.decrypt(ciphertext), AES.block_size).decode())

"""
Hello everyone,

We are out of microchips. Me and my team need more supplies! Hurry up, everyone has to be microchipped! Deliver the package here:

HTB{37.220464, -115.835938}
"""
```
