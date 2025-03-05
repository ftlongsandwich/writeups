from z3 import *

for x in range(64):
    length = x
    s = Solver()
    input = [BitVec(f'char{i}', 32) for i in range(x)]
    for w in input:
        s.add(w >= 0x30)
        s.add(w <= 0x7a)

    c=0x1505

    for i in input:
        c = i ^ c * 0x21

    
    # print(type(c))
    s.add((c&0x00000000ffffffff)==0x9e52fca7)

    if (s.check() == sat):
        m = s.model()
        flag = ''.join(chr(m[i].as_long()) for i in input)
        print(flag)
        tmp = 0x1505
        for i in input:
            tmp = m[i].as_long() ^ tmp * 0x21
        if ((tmp % 2**32)!=0x9e52fca7):
            continue
        print(hex(tmp))
    else:
        print("length " + str(x) + " not sat")