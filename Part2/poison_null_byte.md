![](./poison_null_byte-1785978583673.webp)

this challenge let us create up to 14 chunks, and edit, free or read said chunks 

![](./poison_null_byte-1785978659887.webp)

edithing a chunk will null out the byte after our data, effectively granting us a way to clear flags in chunks with size that is divisible by 0x100

leveraging said apparatus, we can create fake 

