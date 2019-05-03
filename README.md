# Yaef - Yet Another ELF-Injector
Inject an ELF x86_64 shared object into a remote process, and let 
it run as an a independent thread. If specified, use a fake name
to deceive /proc/maps.

All in all, it's a pretty sthealthy & complete solution compared to other ones.

### How does it work
 1. Attach & stop all running threads ([Ptrace](https://www.kernel.org/doc/Documentation/security/Yama.txt))
 2. Create a memory file based on the binary ([memfd_create](http://man7.org/linux/man-pages/man2/memfd_create.2.html))
 3. Hijack remote **__libc_dlopen_mode()** function and load the memfd file
 4. Hijack remote **pthread_create()** function and call specified function

## Installing
``` 
git clone https://github.com/0xN3utr0n/Yaef.git
cd Yaef
make 
```

## Usage
```
Usage: ./Yaef <option> <value>...

	-p	Target process id
	-b	Elf binary path
	-f	Elf binary function name
	-n	File fake name (optional)
```
## Demo

## Bugs
* Multi-thread targets support

## TODO
* Command line args support
* Load binary over the network
