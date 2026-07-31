![](./one_byte-1785507253330.webp)

![](./one_byte-1785507283512.webp)

we are given the option to malloc 16 * 0x60 chunks and to free, edit and read said chunks 

![](./one_byte-1785507344011.webp)

the read option is rather interesting, as we can edit 1 byte more than the requested size

this gains us a few great apparatus, including:

1. clearing the in_use bit for consodilation, which lead to overlapping chunks, which lead to UAF
2. changing the size of a chunk, which let us forge whatever size we want, with the first apparatus 
3. 