#  [Report📝](#Report)
![category](https://img.shields.io/badge/category-forensics-orange)


### Description:
* Your supervisor in the agency just handed you a task. Your mission is to analyze the memory dump from a captured spy's computer and create a report summarizing the findings. Find out the computer's hostname, the administrator's hash and when the memory dump was captured. Flag format: `HTB{hostname_lmhash:ntlmhash_YYYY-MM-DD_HH:MM:SS}`


### Objective:
* Run some volatility plugin in order to perform a basic enumeration.


### Difficulty:
* `Easy` 


### Flag:
* `HTB{ADMINPC-2057_aad3b435b51404eeaad3b435b51404ee:fc525c9683e8fe067095ba2ddc971889_2021-02-05_15:58:23}`

### Challenge:

In this challenge, players are given a windows memory dump file.

First of all by finding the proper image for this dump we can locate the timestamp for the third flag.

```console
volatility -f ADMINPC-2057-20210205-155822.raw imageinfo                          
Volatility Foundation Volatility Framework 2.6
INFO    : volatility.debug    : Determining profile based on KDBG search...
          Suggested Profile(s) : Win7SP1x86_23418, Win7SP0x86, Win7SP1x86_24000, Win7SP1x86
                     AS Layer1 : IA32PagedMemoryPae (Kernel AS)
                     AS Layer2 : FileAddressSpace (/home/wild/Documents/dead_easy/Dumps/dump2/ADMINPC-2057-20210205-155822.raw)
                      PAE type : PAE
                           DTB : 0x185000L
                          KDBG : 0x82772de8L
          Number of Processors : 1
     Image Type (Service Pack) : 1
                KPCR for CPU 0 : 0x80b96000L
             KUSER_SHARED_DATA : 0xffdf0000L
           Image date and time : 2021-02-05 15:58:23 UTC+0000
     Image local date and time : 2021-02-05 07:58:23 -0800

```

  

Timestamp: `2021-02-05 15:58:23`.

For the computer's hostname we must find the virtual address of the `SYSTEM` hive.

```console
volatility -f part2.raw --profile=Win7SP1x86_23418 hivelist                                                               
Volatility Foundation Volatility Framework 2.6
Virtual    Physical   Name
---------- ---------- ----
0x8960a6b8 0x301686b8 [no name]
0x8961a008 0x30fb6008 \REGISTRY\MACHINE\SYSTEM
0x89638218 0x301d4218 \REGISTRY\MACHINE\HARDWARE
0x8b22d968 0x28522968 \??\C:\Users\IEUser\AppData\Local\Microsoft\Windows\UsrClass.dat
0x8b2a89c8 0x2d3b89c8 \??\C:\Windows\ServiceProfiles\NetworkService\NTUSER.DAT
0x8b357600 0x27303600 \??\C:\Windows\ServiceProfiles\LocalService\NTUSER.DAT
0x8fae6808 0x2f0b6808 \SystemRoot\System32\Config\DEFAULT
0x8fb4f9c8 0x2ea979c8 \SystemRoot\System32\Config\SOFTWARE
0x8fbb0008 0x2c547008 \SystemRoot\System32\Config\SECURITY
0x8fbb09c8 0x2c5479c8 \SystemRoot\System32\Config\SAM
0x92c42240 0x2e9d2240 \Device\HarddiskVolume1\Boot\BCD
0x95ba3708 0x2820c708 \??\C:\Users\IEUser\ntuser.dat
0x98163008 0x262cb008 \??\C:\Users\sshd_server\ntuser.dat
0x98171160 0x7ebcc160 \??\C:\Users\sshd_server\AppData\Local\Microsoft\Windows\UsrClass.dat
```

Then by looking the proper hive lists we can find the hostname:

```console
volatility -f part2.raw --profile=Win7SP1x86_23418 printkey -o 0x8961a008 -K "ControlSet001\Control\ComputerName\ActiveComputerName" 
Volatility Foundation Volatility Framework 2.6
Legend: (S) = Stable   (V) = Volatile

----------------------------
Registry: \REGISTRY\MACHINE\SYSTEM
Key name: ActiveComputerName (V)
Last updated: 2021-02-06 01:54:18 UTC+0000

Subkeys:

Values:
REG_SZ        ComputerName    : (V) ADMINPC-2057
```

Hostname: `ADMINPC-2057`.

And for the administrator's hash we will have to use the hashdump plugin.

```console
olatility -f part2.raw --profile=Win7SP1x86_23418 hashdump                                                                         
Volatility Foundation Volatility Framework 2.6
Administrator:500:aad3b435b51404eeaad3b435b51404ee:fc525c9683e8fe067095ba2ddc971889:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
IEUser:1000:aad3b435b51404eeaad3b435b51404ee:fc525c9683e8fe067095ba2ddc971889:::
sshd:1001:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
sshd_server:1002:aad3b435b51404eeaad3b435b51404ee:8d0a16cfc061c3359db455d00ec27035:::
```

Administrator's hash: `aad3b435b51404eeaad3b435b51404ee:fc525c9683e8fe067095ba2ddc971889`.
    
