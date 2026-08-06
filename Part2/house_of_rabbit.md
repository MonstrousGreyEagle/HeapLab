![](./house_of_rabbit-1785979361145.webp)

![](./house_of_rabbit-1785979561747.webp)

the challenge let us malloc 4 fast chunks other chunks, while also letting us modify the "age" variable, which is in user0, slightly below our target

![](./house_of_rabbit-1785979431930.webp)

we are allowed to read 0x10 bytes when the malloc option is used

with that, we can commit a fastbin_dup to link our a fake chunk with
