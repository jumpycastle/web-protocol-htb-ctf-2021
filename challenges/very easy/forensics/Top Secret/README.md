#  [Top Secret 🕵️](#top-secret)
![category](https://img.shields.io/badge/category-forensics-orange)


### Description:
* One of our internal servers containing our top secret documents got compromised. Locate the file that was stolen and calculate the md5sum. `HTB{md5sum of file}`


### Objective:
* Extract the file stolen via ftp.


### Difficulty:
* `very easy` 


### Flag:
* `HTB{6ff7fa6c9aeee44c1aca5db8cf6278cb}`

### Challenge:

For this challenge players are given a pcap file.

After enumerating the pcap file we can see that it only contains FTP traffic.

![](https://i.imgur.com/mMHPxHK.png)

After a small dictionary attack the attacker managed to access the server.

By following the `tcp stream 3` we can see what the attacker did:

```
220 (vsFTPd 3.0.3)
USER Agent_st
331 Please specify the password.
PASS password123
230 Login successful.
SYST
215 UNIX Type: L8
PORT 192,168,1,6,196,163
200 PORT command successful. Consider using PASV.
LIST
150 Here comes the directory listing.
226 Directory send OK.
TYPE I
200 Switching to Binary mode.
PORT 192,168,1,6,141,209
200 PORT command successful. Consider using PASV.
RETR top_secret.pdf
150 Opening BINARY mode data connection for top_secret.pdf (36591 bytes).
226 Transfer complete.
QUIT
221 Goodbye.
```

In the `tcp stream 4` there is the output of the LIST command.

```
-rw-r--r--    1 1003     1003         4854 Feb 04 00:00 incident_23.log
-rwxr-xr-x    1 1003     1003         1752 Feb 04 00:00 mission_55.py
-rwxrwxrwx    1 1003     1003        36591 Feb 03 23:57 top_secret.pdf
```

As we saw above, the attacker retrieved the `top_secret.pdf` file. This can be found in the `tcp stream 5`.

![](https://i.imgur.com/CgzmdLZ.png)

By selecting the `RAW` option in the `Show and save data as` button we can retrieve the pdf file.

```consoles
md5sum secret.pdf 
6ff7fa6c9aeee44c1aca5db8cf6278cb  secret.pdf
```
