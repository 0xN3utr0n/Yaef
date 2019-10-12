#ifndef YAEF_H
#define YAEF_H

#define _GNU_SOURCE

#include <errno.h>
#include <elf.h>
#include <fcntl.h>
#include <limits.h>
#include <stdbool.h>
#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/ptrace.h>
#include <sched.h>
#include <sys/mman.h>
#include <unistd.h>
#include <dirent.h>

enum lib_type {GLIBC, PTHREAD, EVIL};


typedef struct
{
    char *func_name;
    uint64_t func_addr;
    struct user_regs_struct params;
} function_t;

typedef struct
{
    char *lib_name;
    uint64_t lib_addr;
    Elf64_Dyn *dynamic_segmt;
    Elf64_Sym *symtab;
    char *strtab;
    function_t *func;
} library_t;

typedef struct 
{
    pid_t pid;
    int traced;
    struct user_regs_struct syscall;
    library_t *lib[4];
} process_t;

typedef struct
{
    char *path;
    char *name;
    int memfd;
    size_t size;
    char *function;
    uint8_t *mem;
    uint64_t offset;
} binary_t;



extern binary_t * load_payload(const char *, const char *, const char *);
extern library_t * scan_library(const char *, const char *, const pid_t);
extern void __create_thread(process_t *, binary_t *);
extern bool __dl_open(process_t *, const char *, const int, const char *);
extern bool attach_to_process(process_t *);

#endif
