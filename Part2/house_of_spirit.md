![](./house_of_spirit-1785509716907.webp)

![](./house_of_spirit-1785509741868.webp)

the 'user' age and username sandwich our target

![](./house_of_spirit-1785509784147.webp)

![](./house_of_spirit-1785509801795.webp)

as the binary contains no pie, and we got a free heap and libc leak, we can forge a valid fake chunk 

![](./house_of_spirit-1785509923529.webp)

and because we can abuse an overflow bug to change the pointer of the malloc'ed chunk, we can free our fake chunk, and malloc it again to overwrite our target

