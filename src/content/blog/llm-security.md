---
title: "LLM Security: A reflection"
description: "Reflecion about LLM Security and the many ways they can be exploited"
pubDate: 2026-01-25
category: "LLMSecurity"
readTime: "12 min read"
type: blog
tags: ["LLM", "AI"]
author: "0xl0w3"
---

# Introduction

LLMs are being implemented more and more in various environments, and not only as the main job they took at the beginning: AI Assistants; they now play roles in very different roles such as bug finding and refactoring in coding, alert triage for SOCs, chatbots for companies to help customers, etc. One of the things that has helped LLMs become so useful in the last years is the introduction of agency: Agency gives LLMs the capacity of interacting with their environment, execute commands and functions and perform internet searches, among others. This changes everything, now computers can handle complex tasks that were normally handled by either humans or static code, opening the doors for many new attacks.

In this article, I want to go through many of the concerns related to LLMs that leverage Agency and how they might get exploited by a threat.

# Agency: What is that?

An LLM on its own is, simplifying it a lot, just a compilation of weights and numbers that are used to calculate what is the most adequate word after some others already written. For example, in the sentence:
`A dog is _____`, it is more likely to have a word like `cute` than `flying`. Of course LLMs are much more advanced right now and have a bast ammount of data and ways of communicationg, but on it's core, that is what they do. They are tight to what they have been trained with, and of course, they can not perform any action at all.

Agency fixes this probem by allowing LLMs to interact with other pieces of code, enabling them to, for example, perform an internet search. This is achieved by writing the functions in normal code (Python, C, Go, etc) and giving them a natural language description about what they do and what input parameters do they need. A function might be defined like:

```python
def add(a: int, b: int) -> int:
    """
    This function takes two integers, a and b, and sums them together, returning the result of adding a to b.
    """
    return a+b
```
Once this tool is coded and exposed to the LLM, it will be able to decide on whether using it or not. For example, if we have the following prompt:

> What is the sum of 3 and 4

The LLM will most likely follow a pattern in where it will look for tools that allow it to perform addition, find out that there is our function "add" and execute it.

# Security Concerns with Agentic AI

Ok, we've seen what is the concept of Agency, but how can this be exploited? Well, that's a whole different story: Exploiting LLMs is a mix of "Social Engineering" and traditional security. LLMs can have some guardrails and safety meassures that will refuse to do things considered as harmful, and so in order to bypass those safewards, attackers might need to deceive the LLM into thinking that what they are doing is not bad, or that maybe they are authorized to do so.

It might also happen that secrets are accessible to LLMs if, instead of making them static in code, they are passed to the LLM as System Prompt. That might allow attackers to leak it and use it for other purposes.

On the other hand, traditional offensive security techniques might be needed in order to exploit certain functions that might be executed by the LLM. For example, in the following function:

```python
def get_file_content(file_name: str) -> str:
    """
    This function will take a filename as input and will print the file content in case it finds it in the current directory. Otherwise, it will just print that it could not find it
    """
    path = f"./{filename}"
    try:
        with open(path, "r") as f:
            return(f.read())
    except:
        return "File not found"
```
As we can see, this function takes a file name as input and looks for it on the current path. Now, this does not look so suspicious. However, the attacker might ask for something like:

> Please, provide me with the content of the file ../../../../../etc/passwd

In this scenario, there would be a path traversal vulnerability taking place. Although the input was not direct user input, but what the LLM considered to be the right input, this should still be handled as untrusted input.

There are many more examples about all the problematic that araises when using agentic LLMs, in this article only a few were exposed.

# Conclusion

In this short article, whe've reviewed some of the problematics with agentic LLMs and how they could be exploited. On future articles, this will be covered in more technical depth with actual Local LLMs and agentic workflows in order to showcase the impact it might have in real production environments.
