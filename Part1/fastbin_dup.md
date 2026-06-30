![](./fastbin_dup-1782814305354.webp)

![](./fastbin_dup-1782814317855.webp)

the challenge allow us to malloc (fastbin) and free multiple times

![](./fastbin_dup-1782814373544.webp)

with glibc 2.30 and we can free a chunk twice, as the only check against freeing twice a fastbin in this version is checking if the current victim is the same as the last vi