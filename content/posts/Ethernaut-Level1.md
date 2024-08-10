---
title: "Ethernaut - Level 1"
date: 2024-08-10
author: l0w3
---

# Level 1

![](/img/ethernautlevel1/1.png)

New Level!! In this case we are presented with the following instructions. We are asked to:
- Claim Ownership
- Reduce it's balance to 0

Before doing that, let's define this two concepts, since if you are new to the world of Web3, you might not know what this means:

### What is Ownership?

In the context of `Web3`, the owner of a contract is kind of the `Administrator` and will typically have more privileges than a normal user. It is normally set by the first time at the constructor of the contract to the address associated with the person deploying it.

```solidity
contract OwnerSet {
	address public owner;

	constructor () {
		owner = message.sender;
	}
}
```

### Balance on Contracts

On `etherum`, not only physical people have addresses to receive `ETH` but also Smarts Contracts. This is why `payable` functions exist, which can receive `ETH`.

## Solve

Once we have this knowledge, let's dive into the particular exercise:

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract Fallback {
    mapping(address => uint256) public contributions;
    address public owner;

    constructor() {
        owner = msg.sender;
        contributions[msg.sender] = 1000 * (1 ether);
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "caller is not the owner");
        _;
    }

    function contribute() public payable {
        require(msg.value < 0.001 ether);
        contributions[msg.sender] += msg.value;
        if (contributions[msg.sender] > contributions[owner]) {
            owner = msg.sender;
        }
    }

    function getContribution() public view returns (uint256) {
        return contributions[msg.sender];
    }

    function withdraw() public onlyOwner {
        payable(owner).transfer(address(this).balance);
    }

    receive() external payable {
        require(msg.value > 0 && contributions[msg.sender] > 0);
        owner = msg.sender;
    }
}
```

Keeping in mind that the objective is to change the ownership and drain the contract's balance, let's see which functions allow such actions:

#### Change Ownership (1)
```solidity
function contribute() public payable {
        require(msg.value < 0.001 ether);
        contributions[msg.sender] += msg.value;
        if (contributions[msg.sender] > contributions[owner]) {
            owner = msg.sender;
        }
    }
```

What this function is doing is taking a contribution (note it is declared as `payable`) and, if it's less than `0.001 ETH`, it let's it through. Then it adds the contribution to the contributions of the sender, and finally checks if the sender has contributed more than the owner.
How much has the owner contributed? -> As seen in this LOC: `contributions[msg.sender] = 1000 * (1 ether);` the contribution of the owner has been `1000 ETH`.

#### Change Ownership (2)
```solidity
    receive() external payable {
        require(msg.value > 0 && contributions[msg.sender] > 0);
        owner = msg.sender;
    }
```

This second function looks a bit different. That is because it is a `fallback` Function. Note that it is declared as `receive`, and that is because since `Solidity 0.6.0`, a distinction was made between them. According to [the docs](https://docs.soliditylang.org/en/latest/contracts.html#special-functions) :

>A contract can have at most one `receive` function, declared using `receive() external payable { ... }` (without the `function` keyword). This function cannot have arguments, cannot return anything and must have `external` visibility and `payable` state mutability. It can be virtual, can override and can have modifiers.

When looking at the documentation of the `fallback` function, it says the following:

>A `payable` fallback function is also executed for plain Ether transfers, if no [receive Ether function](https://docs.soliditylang.org/en/latest/contracts.html#receive-ether-function) is present.

So long story short, either `receive` and `fallback` functions appear to do very similar things, just that `receive` is oriented towards only receiving funds whereas `fallback` could or could not.

What this function is doing is take the value sent and the previous contributions of the sender and, if they are both greater than 1, it sets the owner to the sender of those transactions.

#### Withdraw
```solidity
function withdraw() public onlyOwner {
        payable(owner).transfer(address(this).balance);
}
```

This function is very simple: If the caller is the owner, it will send the funds to that address.

### Hack

To hack this Smart Contract and drain the account we will follow the following path:

1. Claim Ownership: To do so, we will make a contribution using the `contribute()` function and then execute the `receive()` function to become owners.
2. Call the `withdraw()` function to drain the funds.

![](/img/ethernautlevel1/2.png)

![](/img/ethernautlevel1/3.png)

We see that initially, our address and the address of the contract are different.

We now first do the contribution using `await contract.contribute.sendTransaction({value:1})` which will send `1 wei`

![](/img/ethernautlevel1/4.png)

And after some time, the `ETH` gets to the contract:

![](/img/ethernautlevel1/5.png)

Now we get to the real deal: Calling the `fallback` function with some `Ether`. To do so, we just execute `sendTransaction()` without specifying the function name, like so: `await contract.sendTransaction({value: 1})`

![](/img/ethernautlevel1/6.png)

![](/img/ethernautlevel1/7.png)

Yes!!! We are the owners of the contract. Let's drain the contract:

![](/img/ethernautlevel1/8.png)

Now we can submit the instance and pass the level.

![](/img/ethernautlevel1/9.png)
