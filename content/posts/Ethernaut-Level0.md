---
title: "Ethernaut - Level 0"
date: 2024-08-10
author: l0w3
---

# Level 0

## Introduction

This level is an introduction to make sure we have all the necessary to start our journey on hacking Smart Contracts. We will need:
- MetaMask extension -> This will give us the ability to make transactions and hold our test ether.
- Test Ether -> Those will serve as test coin to interact with the smart contracts without having to spend money on buying Ether (and burning it in some cases). Those can be acquired from various websites. I used https://faucets.chain.link/sepolia. Make sure to use the correct Faucet, in my case I'm using Sepolia. 
## Solve

With those pre-requisites met, let's dive into solving this level. It is quite straight forward and we just have to follow along what the instructions said.

![](/img/ethernautlevel0/1.png)

![](/img/ethernautlevel0/2.png)

![](/img/ethernautlevel0/3.png)

![](/img/ethernautlevel0/4.png)

![](/img/ethernautlevel0/5.png)

![](/img/ethernautlevel0/6.png)

![](/img/ethernautlevel0/7.png)

From here, things can be a little bit trickier. We have to find where the password is being stored. As explained by the initial instructions, the ABI (Application Binary Interface) can be queried to get information about the public methods of the contract. The following command can be used to get all those methods:
![](/img/ethernautlevel0/8.png)
We can see that there is a function called `password` so let's execute it and see what we get.
![](/img/ethernautlevel0/9.png)
Bingo!! Let's authenticate now
![](/img/ethernautlevel0/10.png)
Once executed, it asks for a transaction confirmation. Let's confirm it
![](/img/ethernautlevel0/11.png)
Sweet. Now what? Well, from the step where we got the password we can see that we are missing one function to execute: `getCleared()`.  Let's execute it then
![](/img/ethernautlevel0/12.png)

Awesome, so it looks like we have solved the level. Let's submit the instance.
![](/img/ethernautlevel0/13.png)
Yayyy, the level got solved!!!

