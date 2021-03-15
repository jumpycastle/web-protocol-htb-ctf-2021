# Split

### Description

- Take control of the SpyMobile and guide us to the flag!

### Objective

- Simple anti-debug bypass with debugging.

### Difficulty

- `Easy`

### Flag

- `HTB{d0_th1s_oR_do_th47!?}`

### Release:

- [/release/split.zip](release/split.zip) (`34d189f4c31e93f49ad85e5c987cc5555d891eed2636c8f771e8b55aef869492`)

## Challenge

We're given a single non-stripped binary that prompts us for input.

```shell
$ ./split
[*] Spy Mobile [*]
=> Cruising at 500 mph
Enter destination node: asf
[!] Incorrect destination. Taking a U-Turn [!]
```

Let's open it up in Ghidra to examine the `main` function.

```C
undefined8 main(void)
{
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  setbuf(stdout,(char *)0x0);
  local_94 = 1;
  local_90 = &DAT_00102008;
  local_88 = "v!7Xf-;.2=1/";
  printstr("[*] Spy Mobile [*]\n=> Cruising at 500 mph\nEnter destination node: ");
  fgets(local_78,100,stdin);
  sVar2 = strlen(local_78);
  local_78[sVar2 - 1] = '\0';
  sVar2 = strlen((char *)local_90);
  local_80 = (size_t *)malloc(sVar2 << 2);
  lVar3 = ptrace(PTRACE_TRACEME,0,1,0);
  if (lVar3 == -1) {
    printstr("[!] Anomaly detected [!]\nTerminating...\n");
  }
  else {
    if (local_94 == 1) {
      printstr("[!] Incorrect destination. Taking a U-Turn [!]\n");
    }
    else {
      decrypt((EVP_PKEY_CTX *)local_88,local_90,local_80,local_90,in_R8);
      iVar1 = strcmp(local_78,(char *)local_80);
      if (iVar1 == 0) {
        printstr("[*] Node Activated! [*]\n");
      }
    }
  }
  if (local_10 == *(long *)(in_FS_OFFSET + 0x28)) {
    return 0;
  }
                    /* WARNING: Subroutine does not return */
  __stack_chk_fail();
}
```

First, it prompts us for input and allocates some memory using `malloc`. Next, it calls `ptrace` in order to verify if the binary is being debugged. If this evaluates to true, it prints an error and exits. This can be easily bypassed in gdb by breaking on the return and setting rax to 0.

Next, it checks the value of the variable `local_94`. If this is `1`, then an error is printed and the program exists. If not, it calls the `decrypt` method to decrypt something and call `strcmp`. The decrypted data is probably the flag as it's compared to our input.

At the beginning of main we see that `local_94` is a constant set to `1`, meaning that it will never be any other value. We'll have to debug the binary and change this value manually. 

Run the binary and use `ni` to step until after the ptrace call.

```
$ gdb split
gef➤ b main
gef➤ run
<SNIP>
───────────────────────────────────────────────── code:x86:64 ────
   0x555555555562 <main+183>       add    BYTE PTR [rdi+0x0], bh
   0x555555555568 <main+189>       mov    eax, 0x0
   0x55555555556d <main+194>       call   0x5555555550a0 <ptrace@plt>
 → 0x555555555572 <main+199>       cmp    rax, 0xffffffffffffffff
   0x555555555576 <main+203>       jne    0x55555555558b <main+224>
   0x555555555578 <main+205>       lea    rdi, [rip+0xaf9]        # 0x555555556078
   0x55555555557f <main+212>       call   0x5555555551b9 <printstr>
   0x555555555584 <main+217>       mov    eax, 0x0
   0x555555555589 <main+222>       jmp    0x5555555555f0 <main+325>
──────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "split", stopped 0x555555555572 in main (), reason: SINGLE STEP
───────────────────────────────────────────────────── trace ────
[#0] 0x555555555572 → main()
──────────────────────────────────────────────────────────────────
gef➤  set $rax=0
gef➤  ni
```

Keep stepping until we reach the variable comparison. Here we will set the RIP pointer to an instruction after the comparison.

```
$ gdb split
<SNIP>
────────────────────────────────────────────────── code:x86:64 ────
   0x555555555588 <main+221>       add    bl, ch
   0x55555555558a <main+223>       xor    DWORD PTR gs:[rbp-0x8c], 0x1
→  0x555555555592 <main+231>       cmp    DWORD PTR [rbp-0x8c], 0x0
   0x555555555599 <main+238>       je     0x5555555555df <main+308>	TAKEN [Reason: Z]
   0x55555555559b <main+240>:	   mov    rdx,QWORD PTR [rbp-0x78]
───────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "split", stopped 0x555555555599 in main (), reason: SINGLE STEP
────────────────────────────────────────────────────── trace ────
[#0] 0x555555555599 → main()
──────────────────────────────────────────────────────────────────
gef➤ set $rip=0x55555555559b
gef➤ ni
```

This will continue execution to the decrypt function. Step over it and stop at the strcmp call, where we can find the flag.

```
$ gdb split
<SNIP>
→ 0x5555555555c3 <main+280>       call   0x555555555080 <strcmp@plt>
   ↳  0x555555555080 <strcmp@plt+0>   jmp    QWORD PTR [rip+0x2fba]        # 0x555555558040 <strcmp@got.plt>
      0x555555555086 <strcmp@plt+6>   push   0x5
      0x55555555508b <strcmp@plt+11>  jmp    0x555555555020
      0x555555555090 <malloc@plt+0>   jmp    QWORD PTR [rip+0x2fb2]        # 0x555555558048 <malloc@got.plt>
      0x555555555096 <malloc@plt+6>   push   0x6
      0x55555555509b <malloc@plt+11>  jmp    0x555555555020
────────────────────────────────────────── arguments (guessed) ────
strcmp@plt (
   $rdi = 0x00007fffffffdf70 → 0x0000000000000000,
   $rsi = 0x00005555555596b0 → "HTB{d0_th1s_oR_do_th47!?}",
   $rdx = 0x00005555555596b0 → "HTB{d0_th1s_oR_do_th47!?}",
   $rcx = 0x0000000000000000
)
───────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "split", stopped 0x5555555555c3 in main (), reason: SINGLE STEP
───────────────────────────────────────────────────── trace ────
[#0] 0x5555555555c3 → main()
```

The string `HTB{d0_th1s_oR_do_th47!?}` is the flag and the password.
