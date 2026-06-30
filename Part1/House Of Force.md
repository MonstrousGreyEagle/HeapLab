![](../img/House%20Of%20Force-1782804271166.webp)

the program let us write 8 bytes more than the allocated space, letting us overwrite the """total""" space for heap, which let us do funky stuff

![](../img/House%20Of%20Force-1782804359864.webp)

the program also provide us the heap base, which allow us to calculate the distance from our target

![](../img/House%20Of%20Force-1782804408264.webp)

![](../img/House%20Of%20Force-1782804431287.webp)

pie isnt enabled so we can overflow the pointer to point the malloc pointer? (i didnt remember the name) to malloc a block of data in bss instead of the heap