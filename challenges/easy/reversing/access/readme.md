# Access

### Description

- Please help us to access this classified program.

### Objective

- Single byte XOR decryption.

### Difficulty

- `Easy`

### Flag

- `HTB{l3t_me_1n_l3t_meeee_in!!}`

### Release:

- [/release/access.zip](release/access.zip) (`812ef2d3b4cd8111c1aebede6eca2905b701f8cb3060908142a9dd7b520dea6e`)

## Challenge

We're given a 64-bit non-stripped binary, which prompts us for a credentials.

```shell
$ ./access

Global Secure Console v1.0

Welcome Agent,
Please enter your credentials to continue.

AgentID\:> test
Access Denied!
```

Let's open it in Ghidra and look at the `main` function. 

```C
undefined8 main(void)

{
  int iVar1;
  undefined8 uVar2;
  long in_FS_OFFSET;
  char local_58 [32];
  char local_38 [40];
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  setbuf(stdout,(char *)0x0);
  printstr("\nGlobal Secure Console v1.0\n\n",0);
  printstr("Welcome Agent, \n",0);
  printstr("Please enter your credentials to continue.\n\n",0);
  printstr("AgentID\\:> ",0);
  fgets(local_58,0x20,stdin);
  iVar1 = strcmp(local_58,"31337\n");
  if (iVar1 == 0) {
    printstr("Pin\\:> ",0);
    fgets(local_38,0x20,stdin);
    uVar2 = checkpin(local_38);
    if ((int)uVar2 == 0) {
      printstr("Access Granted!",0);
    }
    else {
      printstr("Access Denied!",1);
    }
  }
  else {
    printstr("Access Denied!",1);
  }
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return 0;
}
```

It first checks if the entered `AgentID` is equal to `31337` and then prompts for a pin. The input pin is then passed to the `checkpin` function. 

```C
undefined8 checkpin(char *param_1)
{
  size_t sVar1;
  int local_24;
  
  local_24 = 0;
  while( true ) {
    sVar1 = strlen(param_1);
    if (sVar1 - 1 <= (ulong)(long)local_24) {
      return 0;
    }
    if (((&enc_flag)[local_24] ^ 0x20) != param_1[local_24]) break;
    local_24 = local_24 + 1;
  }
  return 1;
}
```

This function XOR decrypts a string in the global buffer `enc_flag` and then compares it with the input. The XOR key appears to be `0x20`.

```shell
$ python
Python 3.8.6 (default, Sep 30 2020, 04:00:38)
[GCC 10.2.0] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> from pwn import xor
>>> enc = "\x4C\x13\x54\x7F\x4D\x45\x7F\x11\x4E\x7F\x4C\x13\x54\x7F\x4D\x45\x45\x45\x45\x7F\x49\x4E\x01\x01"
>>> xor(enc, 0x20)
b'l3t_me_1n_l3t_meeee_in!!'
```

The key works and we gain the pin which is also the flag.

