![](./one_byte-1785507253330.webp)

![](./one_byte-1785507283512.webp)

we are given the option to malloc 16 * 0x60 chunks and to free, edit and read said chunks 

![](./one_byte-1785507344011.webp)

the read option is rather interesting, as we can edit 1 byte more than the requested size

this gains us a few great apparatus, including:

1. clearing the in_use bit for consodilation, which leads to overlapping chunks, which leads to UAF
2. changing the size of a chunk, which let us forge whatever size we want, with the first apparatus 

because the small bin is a linked list, when IO_flush_all_lockp walk through the chain in IO_list_all, some few bins are treated as file, such as the 0x40 bin, the 0xb0 bin, etc

by forging some fake chunk with fake size and use malloc to push the fake chunk into the coresponding smallbin, we can guild the IO_FILE chain to our heap

by consodilating a chunk that being freed with a chunk that is live, then malloc'ing a chunk out of the hypothetical freed chunk, our live chunk that is consolidated is treated as a freed chunk, linked against the unsorted bin