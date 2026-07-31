
![](./house_of_lore-1785510069397.webp)

![](./house_of_lore-1785510083294.webp)

the username is above our target, by which we can forge a fake freed chunk, as we can edit 0x20 bytes

![](./house_of_lore-1785510131326.webp)

with the free heap and libc leak, we can link our fake chunk to a freed chunk on the heap that belong to a small bin

![](./house_of_lore-1785510196498.webp)

and because the edit option does not have a check for if a chunk is freed, which is a UAF bug, we can then link the freed chunk to the chunk in our bss

```

```