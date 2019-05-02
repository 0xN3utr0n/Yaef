/*
 * Yaef.h
 *
 * Copyright 2019 0xN3utr0n <0xN3utr0n at pm.me>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 * MA 02110-1301, USA.
 *
 *
 */

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


typedef struct function
{
    char *func_name;
    uint64_t func_addr;
    struct user_regs_struct params;
} function_t;

typedef struct library
{
    char *lib_name;
    uint64_t lib_addr;
    Elf64_Dyn *dynamic_segmt;
    Elf64_Sym *symtab;
    char *strtab;
    function_t *func;
} library_t;

typedef struct process_info
{
    pid_t pid;
    int traced;
    struct user_regs_struct syscall;
    library_t *lib[4];
} process_t;

typedef struct binary_info
{
    char *path;
    char *name;
    int memfd;
    size_t size;
    char *function;
    void *mem;
    uint64_t offset;
} binary_t;


static inline int memfd_create(const char *, unsigned int);
static pid_t * list_threads(const pid_t);
static bool attach_to_process(process_t *);
static bool aux_read(void *, const size_t, void *, const pid_t);
static bool aux_write(void *, const size_t, void *, const pid_t);
uint64_t search_library(const char *,const pid_t);
bool search_function(library_t *, const pid_t);
bool search_dyn_segment(library_t *, const pid_t);
Elf64_Shdr * elf_section_lookup(const char *, uint8_t *, const Elf64_Ehdr *);
uint64_t hijack_syscall(process_t *, struct user_regs_struct *);
uint64_t hijack_function(function_t *, pid_t);
uint64_t inject_string(const char *, process_t *);
static bool flow_advance(process_t *);
binary_t * load_payload(const char *, const char *, const char *);
binary_t * scan_elf(int, const char *);
library_t * scan_library(const char *, const char *, const pid_t);
static void aux_exit(char *, process_t *, binary_t *);
void __create_thread(process_t *, binary_t *);
bool __dl_open(process_t *, const char *, const int, const char *);

#endif
