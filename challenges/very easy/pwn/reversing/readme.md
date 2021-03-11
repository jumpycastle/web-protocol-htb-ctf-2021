# Check

### Description

- Can you help us reveal the secret?

### Objective

- Function call trace to discover the flag.

### Difficulty

- `very easy`

### Flag

- `HTB{ch3ck_anD_r3checK_aga1n!}`

### Release:

- [/release/check.zip](release/check.zip) (`a1d4960f3bda08a87bbadc3b2b0fc143b393183e99b6629e27486f2e8b660e0b`)

## Challenge

The binary prompts us for the secret and then exits.

```shell
$ ./check
TopSpy Association
Enter the secret: asd
Incorrect! >_<
```

Running strings on the binary doesn't reveal any potential secret. Let's use `ltrace` to check if we can catch some library calls.

```
$ ltrace ./check
setbuf(0x7f8a6afee520, 0)                                                                  = <void>
printf("TopSpy Association\nEnter the sec"...TopSpy Association
Enter the secret: )                                                            = 37
fgets(test
"test\n", 40, 0x7f8a6afed800)                                = 0x7ffd55bfde00
strlen("test\n")                                             = 5
strcmp("ch3ck_anD_r3checK_aga1n!", "test")                   = -17
```

We see a call to strcmp with our input and the string `ch3ck_anD_r3checK_aga1n!`. Submit this string works and give us the flag.

```shell
$ ./check
TopSpy Association
Enter the secret: ch3ck_anD_r3checK_aga1n!
Welcome Agent, heres's a small gift: HTB{ch3ck_anD_r3checK_aga1n!}
```





