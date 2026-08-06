![](./poison_null_byte-1785978583673.webp)

this challenge let us create up to 14 chunks, and edit, free or read said chunks 

![](./poison_null_byte-1785978659887.webp)

edithing a chunk will null out the byte after our data, effectively granting us a way to clear flags in chunks with size that is divisible by 0x100

![](./poison_null_byte-1785978800948.webp)

and because the binary use libc 2.25, size vs prev_size check doesnt exist, thus making it possible to create overlapping chunks by clearing pre_inuse, faking prevsize and let the freed chunk consolidate backward, over a live chunk

and because we can read and existing chunk, we can leak libc_base and heap_base, then edit our existing freed chunk metadata with our overlapping live 

