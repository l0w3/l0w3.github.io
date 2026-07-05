---
title: "Hardware Hacking Gone Wrong"
description: "The reality of starting out in Hardware Hacking"
pubDate: 2026-07-05
category: "Hardware Hacking"
type: blog
readTime: "20 min read"
tags: ["Hardware Hacking", "Soldering", "Reversing"]
author: "0xl0w3"
---

# Introduction

At first, when I thought about what I wanted to show on this article, I thought I would be able to do all what other researchers such as Matt Brown or stacksmashing do on their videos. However, reality was very different. I thought I would be able to extract the firmware, reverse it easily, getting some misconfigurations, maybe hardcoded credentials... You know, just the typical stuff that is shown on all those videos and blogposts. The truth was that I had to desoder the chip from the board (mind that that was my first real experience with sodering outside the typical pin sodering on Arduinos), extract the firmware off-board, only to find out that what I got was not at all what I would expect, and to cherry up, I ended up de-sodering some micro-capacitors of the board when trying to soder back the chip (remember, first experience sodering).

What I though it would be a cool weekend project ended up being a weekend of trying to soder back components that I am sure that they do not even reach the half-millimeter size, a lot of frustration from not being able to extract the firmware I was expecting, and not drinking water at all.

So yeah, if you were hoping to see another cool blogpost about Hardware Hacking, this might not be what you were hoping for. However, if you would like to see what a first real experience looks like, stick around!

# How It All Started

About two years ago I met @dreg, a Hardware Hacking Spanish researcher. Before meeting him, I did not even know that Hardware Hacking was a thing, but after some time of speaking with him, I really got interested and joined the Hardware Hacking community. I took a basic course that @dreg offers on a regular basis for free, where I could learn the very basics (Bus Pirate, Firmware Extraction, Electronics Refresher, etc). He offered us the possibility to buy a kit with some handy stuff so we did not have to buy it ourselves separately, which I found really nice. However, after that experience, I did not dig further.

About a week ago, I went on a small trip to Italy and while going around the store I found a very cheap TP-Link IP camera for around 15€. I immediately thought about hardware hacking again, and since I already had all the basic hardware, I thought it would be a great idea. I also bought some extra things online so I would be prepared in case of needing it (and thank god I did that).

Immediately after arriving home I started to tear down the camera, and my adventure began.

![Hardware](/images/hardware-hacking-gone-wrong/image.png)

# Teardown

The first thing I did was to tear down the camera, which was actually not hard (maybe the easiest part of the whole project). In order to do it I just tried to find all the plastic joints and just sticked a piece of plastic between them and tried to pop it out. Eventually I could take the required covers to get to the main board. Until now it was still fun, but after that, everything went downhill.

![Mainboard](/images/hardware-hacking-gone-wrong/IMG_2238.jpeg)

# Extracting Firmware

## Try #1
Once I did have access to the mainboard, I could finally do the cool stuff. I first identified the chip, an XMC 25QH64D.

![Chip Identification](/images/hardware-hacking-gone-wrong/IMG_2246.jpeg)

A quick search on the internet reveals the Datasheet from the chip, which includes a connection diagram (although in this case it was fairly easy to know that it followed the SOP8 formfactor).

![SOP8 Diagram](/images/hardware-hacking-gone-wrong/image2.png)

Cool!! Now I just have to stick the probes onto the chip, wire it up to the Bus Pirate and dump the firmware, as easy as it seems on the tutorials... Right?

![Probes on Chip](/images/hardware-hacking-gone-wrong/IMG_2248.jpeg)

![Chip connected to Bus Pirate](/images/hardware-hacking-gone-wrong/IMG_2249.jpeg)

Turns out it was not as easy as expected. After multiple tries, the FlashRom program could not correctly detect which SPI chip I was using, even when specifying it manually. This was a bit disappointing and got me spending a whole afternoon researching about the SPI protocol, checking the wiring, ensuring that the right voltage was arriving... Nothing seemed to work, the chip was still not detected.

```shell
root@fedora:/home/0xl0w3/Documents# flashrom -p buspirate_spi:dev=/dev/ttyUSB0 -V
flashrom v1.8.0-devel (git:v1.7.0-66-gee38320f) on Linux 7.0.12-201.fc44.x86_64 (x86_64)
flashrom is free software, get the source code at https://flashrom.org
 
flashrom was built with GCC 16.1.1 20260515 (Red Hat 16.1.1-2), little endian
Command line (3 args): flashrom -p buspirate_spi:dev=/dev/ttyUSB0 -V
Initializing buspirate_spi programmer
Detected Bus Pirate hardware 3.0
Detected Bus Pirate firmware 5.10
Using SPI command set v2.
Bus Pirate firmware 6.1 and older does not support SPI speeds above 2 MHz. Limiting speed to 2 MHz.
It is recommended to upgrade to firmware 6.2 or newer.
SPI speed is 2MHz
Bus Pirate v3 or newer detected. Set serial speed to 2M baud.
Serial speed is 2000000 baud
Raw bitbang mode version 1
Raw SPI mode version 1
Driving AUX high.
The following protocols are supported: SPI.
[SNIP]
Probing for XMC XM25QH64C/XM25QH64D, 8192 kB: RDID byte 0 parity violation. compare_id: id1 0x00, id2 0x00
Probing for XMC XM25QU64C/XM25LU64C, 8192 kB: RDID byte 0 parity violation. compare_id: id1 0x00, id2 0x00
Probing for XMC XM25QH64A, 8192 kB: RDID byte 0 parity violation. compare_id: id1 0x00, id2 0x00
[SNIP]
Probing for Generic unknown SPI chip (RDID), 0 kB: RDID byte 0 parity violation. compare_id: id1 0x00, id2 0x00
Probing for Generic unknown SPI chip (REMS), 0 kB: compare_id: id1 0x00, id2 0x00

No EEPROM/flash device found.
Note: flashrom can never write if the flash chip isn't found automatically.
Raw bitbang mode version 1
Bus Pirate shutdown completed.
Runtime from programmer init to shutdown: 0min 2sec
```
At this moment I started researching about what could be the problem. I tried feeding 3.3V to the `WS` and `HOLD` legs, however, that seemed to have no effect on the detection capabilities of flashrom.

I also tried connecting the power unit to the camera, as I thought that the multiple board components were draining the power supplied by the Bus Pirate; however, that also did not resolve the problem.

After many tried and failed attempts, I decided that it might be better to just take the chip out and analyze it separately. I was avoiding that as I did not have much experience with soldering.

Looking at it in perspective and after having investigated further, I have a few hypotheses for why this didn't work:

- I connected the probes incorrectly, either making contact with other legs accidentally or with a poor contact surface.
- The board was absorbing the power supplied by the Bus Pirate when no external power source was connected, causing insufficient power to reach the chip.
- When external power was plugged in, other components communicating with the SPI Flash memory may have interfered with the reads, preventing accurate detection.

That said, the power-related theories are less likely to be plausible as I checked the voltages on the legs many times and consistently got voltage readings within the SPI Flash chip's working range.

## Try #2

After the first try failed, I decided to get some use out of my brand new soldering station. Not the best one, that is for sure, but I guess it does the job, specially when you are a hobbyist starting out and don't want to spend a lot of money. After watching some tutorials (and realizing I was still missing some of the material) I decided to give it a go and start desodering

![Sodering Iron](/images/hardware-hacking-gone-wrong/EBC440EA-12D7-4C17-9464-72D5CCD55A7A.JPG)

![Desodered Chip (1)](/images/hardware-hacking-gone-wrong/IMG_2256.jpeg)

![Desodered Chip (2)](/images/hardware-hacking-gone-wrong/IMG_2257.jpeg)

That was not actually that bad (except for that white "glue", but we will leave that for later).

>Cool, now that I have the chip out I can finally analyze it.

That is what I thought before hitting another wall. After having extracted the chip from the board, I placed it into a SOP8 socket and connected it to a SPI programmer, however, I was still getting the exact same output as when being analyzed on the board itself. I don't actually know why; maybe I tried when the chip was still too hot from being desodered, maybe something was not correctly connected or the legs had some residues that made the connection unstable... I do not really know what could've gone wrong there and I might be revisiting this as it should've worked.

## Try #3

After the fiasco with the previous tries, I checked that my devices were actually working. I had an SPI Flash Memory from the kit that @dreg sent me out for the workshop, so I wired it up to the Bus Pirate and it actually worked! I desodered the chip and placed it into the SPI programmer and it worked again, so I could rule out that the analysis hardware was faulty.

![SPI Flash on board](/images/hardware-hacking-gone-wrong/IMG_2253.jpeg)

At that point I was really frustrated. I did fire up the camera before starting anything and it did work, so it was not a faulty device either. After some time I just tested something I genuinely thought it would not work: Just sodering the chip onto the SPI board that came with the kit from the course. I sodered it again, connected the Bus Pirate to the pins and this time, I connected to the Bus Pirate interface and ran the commands manually. After hopelessly pressing enter, I finally got some output:

```shell
SPI>[0x9f r r r]
/CS ENABLED
WRITE: 0x9F
READ: 0x20
READ: 0x40
READ: 0x17
/CS DISABLED
```
THE SPI FLASH GOT DETECTED. The bytes 0x20 0x40 0x17, which align exactly with the actual model that we have. After this surprise, I ran flashrom again and finally got the SPI flash memory detected. With all the hype, I forgot to take a screenshot or save the output, but trust me on this one, I was really really excited to finally see some output.

![Extracted Firmware](/images/hardware-hacking-gone-wrong/image3.png)

Now it is finally time for some actual analysis and reverse engineering (or that's what I thought).

# (Lite) Firmware Reverse Engineering

Great, so after finally being able to extract the firmware it's time to analyze it. For this the absolute most popular tool is `binwalk` which can identify and extract many file formats from a binary file, making the analysis step easier. Let's do that and read the files created.

```shell
binwalk -Me camera-firmware1.img
```
![Files on Firmware (1)](/images/hardware-hacking-gone-wrong/image4.png)

![Files on Firmware (2)](/images/hardware-hacking-gone-wrong/image5.png)

Great!! So now that I finally got to extract the firmware, I wanted to try to find some basic data, such as the SSID or the Password of my WiFi network, as well as other interesting data, however, I did not find any file that contained this information. I might need to reverse engineer the program on the firmware itself (located on /bin/main), but I will cover that on another article, perhaps one that is a bit more optimistic ;).

I observed as well that there is no actual "filesystem", and that the strings on the raw img are fairly reduced.

```shell
0xl0w3@fedora:~/Documents/hh$ strings camera-firmware1.img  -n 10 | wc -l
302
0xl0w3@fedora:~/Documents/hh$
```

I do not know why, but that really seems like something is missing. Perhaps there is another Flash memory on the chip that I did not see, or maybe one of the chips it uses has an integrated flash where the actual filesystem is saved. In order to confirm that I wanted to connect to the UART interface that I observed on the board and check if I could manage to get a shell, but for that I needed to soder back the SPI Flash onto the board.

# Sodering SPI Flash Back

What I thought would be easy turned out to be a really bad nightmare. When trying to soder back the SPI Flash onto the board, I thought it would be piece of cake: Just place the chip on the pads, apply a bit of heat with the hot air gun and when it wiggles a bit on the pads, you can turn off the hot air gun and after a few seconds let go of the chip and it should stay in place.

However, when proceeding to do so I accidentally touched a small capacitor that was right above the SPI flash, and that turned out to be a really big mistake, as that tiny capacitor made me lose almost an entire day working on the board trying to get it back in place. Not enough with that, while trying to put that capacitor back on the board, I ended up knocking out a diode and an even smaller capacitor.

![Board with capacitors and diode out](/images/hardware-hacking-gone-wrong/87CEA057-0168-49D5-A540-3B3EE045866F.JPG)

I would not be exaggerating if I said that I spent more than 8 hours trying to get everything back. At that moment I really regretted not getting some proper insights on how to soder and how to perform this type of works before actually digging in.

After all those headaches, I decided that the capacitors were not worth the effort and only got back the diode. My guess on the capacitors was that they were there probably to stabilize the signals but did not actually have a protecting function, so the circuit should work fine without them.

Sure enough, after all the sodering work, I assembled back some parts of the camera and plugged it in to see if it was still working:

![Working Camera](/images/hardware-hacking-gone-wrong/FFD63CA6-6472-412A-8D84-9CD8F3842303(1).JPG)

And to my great surprise, the camera actually turned on and even started sending images back!

![Images](/images/hardware-hacking-gone-wrong/image6.png)

I can not describe how happy I was to see that after all the camera was still kind of working. That really encouraged me to keep trying.

# Whats next?

After the crazy weekend I had, I decided to leave it there. I needed to take a break and rest for a bit, as it has been really intense. On the following weeks I might be connecting to the UART port to try to retrieve more information and see if there is a shell I can use to browse an actual file system. Otherwise I will just start out by reversing the `main` program located at `/bin` to try to find out more information.

# Aftermath & Lessons Learned

After all the chaos, all the sodering and de-sodering, etc, this is how the board looks right now:

![Board aftermath (1)](/images/hardware-hacking-gone-wrong/image7.png)
![Board aftermath (2)](/images/hardware-hacking-gone-wrong/image8.png)

Recall the white substance on my working surface on previous sections? Well, that was some product that the board had, that when applying heat just melted and leaked into some of the connectors, which I had to open up in order to clean them. You might also see that other connectors are burned and broken... yup, I accidentally melted them as well... Turns out that when you direct air at about 300ºC to some plastic components, they apparently melt, totally unexpected.

The damage unfortunately does not end here. My sodering iron was brand new, and so were the tips. Still, my dumbass head thought it would be a good idea to put them at 350ºC right away. They burned. Now the tin does not properly stick to the tips and I assume them to not be usable anymore. 

Other than that, everything appears to be working, no other damage aside from the aesthetics has been made and it looks like I can perform further research on it.

## Lessons Learned

- Some components and materials such as Flux or Kapton Tape seem to be a "nice to have", but now I feel them like a must. If I had Flux, all the sodering and de-sodering work would've been much easier. If I had Kapton Tape, a lot of damage I did to the board could've been prevented.
- Before using new tips on a sodering iron, pre-heat them at around 200-250ºC and let them stay like that for a couple of minutes. After that increase the temperature progressively until the desired temperature. 400ºC is also way too much, as soon as the tin starts melting easily, that is the right temperature.
- Clean the tips of the sodering iron regularly and re-tin them before working and leaving it off, that way the heat distributes far faster than if not done.
- Firmwares come in many sizes and shapes, and it is bold to expect that all will have a great filesystem with all the files available to be read. 
- Breaking (cheap) things is the best way to learn, keep trying until getting it done, the worst that can happen is that it will (still) not work.

# Conclusions

After this weekend, I can say that not everything is like it appears to be. On youtube videos or other blog posts, it feels like hardware security is just easy. Everyone makes it look uncomplicated and straightforward, but that was not my experience at all. Perhaps the target I chose was not the best to start with, but in the end it's challenges that make us improve and learn new things.

Overall I am quite proud of what I achieved while doing this research. I managed to learn a ton, specially about sodering and de-sodering. I hope that by the next blog post I manage to perform an actual Firmware Reverse Engineering and get more insights into how it actually works. For now, I focused almost entirely on the hardware side, not the firmware itself; running binwalk was as far as the reversing got.

Now I will let it rest for a bit and continue other research projects I have on my bucket list, but I will surely come back.

# Extra: Quotes that kept me motivated

> There has to be another way, there is always another way

> Someone did that for the first time, so can I

> If it burns, it only costed 15€, have fun

> OMG I'm dumb