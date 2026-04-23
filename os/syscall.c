#include "syscall.h"
#include "console.h"
#include "defs.h"
#include "loader.h"
#include "syscall_ids.h"
#include "timer.h"
#include "trap.h"
#include "stat.h"

uint64 console_write(uint64 va, uint64 len)
{
	struct proc *p = curr_proc();
	char str[MAX_STR_LEN];
	int size = copyinstr(p->pagetable, str, va, MIN(len, MAX_STR_LEN));
	tracef("write size = %d", size);
	for (int i = 0; i < size; ++i) {
		console_putchar(str[i]);
	}
	return len;
}

uint64 console_read(uint64 va, uint64 len)
{
	struct proc *p = curr_proc();
	char str[MAX_STR_LEN];
	tracef("read size = %d", len);
	for (int i = 0; i < len; ++i) {
		int c = consgetc();
		str[i] = c;
	}
	copyout(p->pagetable, va, str, len);
	return len;
}

uint64 sys_write(int fd, uint64 va, uint64 len)
{
	if (fd < 0 || fd > FD_BUFFER_SIZE)
		return -1;
	struct proc *p = curr_proc();
	struct file *f = p->files[fd];
	if (f == NULL) {
		errorf("invalid fd %d\n", fd);
		return -1;
	}
	switch (f->type) {
	case FD_STDIO:
		return console_write(va, len);
	case FD_INODE:
		return inodewrite(f, va, len);
	default:
		panic("unknown file type %d\n", f->type);
	}
}

uint64 sys_read(int fd, uint64 va, uint64 len)
{
	if (fd < 0 || fd > FD_BUFFER_SIZE)
		return -1;
	struct proc *p = curr_proc();
	struct file *f = p->files[fd];
	if (f == NULL) {
		errorf("invalid fd %d\n", fd);
		return -1;
	}
	switch (f->type) {
	case FD_STDIO:
		return console_read(va, len);
	case FD_INODE:
		return inoderead(f, va, len);
	default:
		panic("unknown file type %d\n", f->type);
	}
}

__attribute__((noreturn)) void sys_exit(int code)
{
	exit(code);
	__builtin_unreachable();
}

uint64 sys_sched_yield()
{
	yield();
	return 0;
}

uint64 sys_gettimeofday(uint64 val, int _tz)
{
	struct proc *p = curr_proc();
	uint64 cycle = get_cycle();
	TimeVal t;
	t.sec = cycle / CPU_FREQ;
	t.usec = (cycle % CPU_FREQ) * 1000000 / CPU_FREQ;
	copyout(p->pagetable, val, (char *)&t, sizeof(TimeVal));
	return 0;
}

uint64 sys_getpid()
{
	return curr_proc()->pid;
}

uint64 sys_getppid()
{
	struct proc *p = curr_proc();
	return p->parent == NULL ? IDLE_PID : p->parent->pid;
}

uint64 sys_clone()
{
	debugf("fork!");
	return fork();
}

static inline uint64 fetchaddr(pagetable_t pagetable, uint64 va)
{
	uint64 *addr = (uint64 *)useraddr(pagetable, va);
	return *addr;
}

uint64 sys_exec(uint64 path, uint64 uargv)
{
	struct proc *p = curr_proc();
	char name[MAX_STR_LEN];
	copyinstr(p->pagetable, name, path, MAX_STR_LEN);
	uint64 arg;
	static char strpool[MAX_ARG_NUM][MAX_STR_LEN];
	char *argv[MAX_ARG_NUM];
	int i;
	for (i = 0; uargv && (arg = fetchaddr(p->pagetable, uargv));
	     uargv += sizeof(char *), i++) {
		copyinstr(p->pagetable, (char *)strpool[i], arg, MAX_STR_LEN);
		argv[i] = (char *)strpool[i];
	}
	argv[i] = NULL;
	return exec(name, (char **)argv);
}

uint64 sys_wait(int pid, uint64 va)
{
	struct proc *p = curr_proc();
	int *code = (int *)useraddr(p->pagetable, va);
	return wait(pid, code);
}

uint64 sys_spawn(uint64 va)
{
    char filename[128];
    struct proc *p = curr_proc();
    struct proc *np;

    if (copyinstr(p->pagetable, filename, va, 128) < 0) {
        return -1;
    }

    // get inode from filename
    struct inode *ip = namei(filename);
    if (ip == 0) {
        return -1;
    }

    ivalid(ip);

    // allocate process
    np = allocproc();
    if (np == 0) {
        iput(ip);
        return -1;
    }

    np->parent = p;

    // load program into process
    if (bin_loader(ip, np) < 0) {
        iput(ip);
        return -1;
    }

    iput(ip);  // release inode

    np->state = RUNNABLE;
    return np->pid;
}


uint64 sys_set_priority(long long prio)
{
	// TODO: your job is to complete the sys call
	if (prio<2){
		return -1;
	}

	struct proc *p = curr_proc();
	p->priority = prio;
	p->pass = BIG_STRIDE/p->priority;
    return prio;
}


uint64 sys_mmap(void * start, unsigned long long len, int port, int flag, int fd)
{
	uint64 va_start = (uint64) start; //void pointer
    // insufficient physical memory
    if (len > (1 << 30)) {
        return -1;
    }
	// length is a multiple of page size
    if (va_start % PGSIZE != 0) {
        return -1;
    }
    // port must have at least one of bits 0-2 set, no more
    if ((port & ~0x7) != 0 || (port & 0x7) == 0) {
        return -1;
    }

    struct proc *p = curr_proc();

    // Check that no VA in the range is already mapped
    for (uint64 va = va_start; va < va_start + len; va += PGSIZE) {
        if (walkaddr(p->pagetable, va) != 0) { return -1; };
    }

    // Build permission bits from port
    int perm = PTE_U;
    if (port & 1) perm = perm | PTE_R;
    if (port & 2) perm = perm | PTE_W;
    if (port & 4) perm = perm | PTE_X;

    // loc one page at a time, memset, then map via mappages
	// returns a pointer that kernal can use
    for (uint64 va = va_start; va < va_start + len; va += PGSIZE) {
        void *pa = kalloc();
		if (!pa) { return -1; }

        memset(pa, 0, PGSIZE);
        // mappages for a single page (size = PGSIZE)
		// creates a page table address
        if (mappages(p->pagetable, va, PGSIZE, (uint64)pa, perm) < 0) {
            return -1;
        }
    }

    return 0;
}

uint64 sys_munmap(void * start, unsigned long long len)
{
	uint64 va_start = (uint64) start;

	//fail if memory is not allocated
	if (len == 0) {
		return 0;
	}

    if (va_start % PGSIZE != 0) {
        return -1;
    }

    // end of range, rounded up
	len = PGROUNDUP(len);
    uint64 va_end = va_start + len;

    struct proc *p = curr_proc();

    // verify all pages in range are mapped
    for (uint64 va = va_start; va < va_end; va += PGSIZE) {
        if (walkaddr(p->pagetable, va) == 0) {
			return -1;
		}
    }

    // number of pages
    uint64 npages = len / PGSIZE;

    // unmap and free physical memory
    uvmunmap(p->pagetable, va_start, npages, 1);

    return 0;
}


uint64 sys_openat(uint64 va, uint64 omode, uint64 _flags)
{
	struct proc *p = curr_proc();
	char path[200];
	copyinstr(p->pagetable, path, va, 200);
	return fileopen(path, omode);
}

uint64 sys_close(int fd)
{
	if (fd < 0 || fd > FD_BUFFER_SIZE)
		return -1;
	struct proc *p = curr_proc();
	struct file *f = p->files[fd];
	if (f == NULL) {
		errorf("invalid fd %d", fd);
		return -1;
	}
	fileclose(f);
	p->files[fd] = 0;
	return 0;
}

int sys_fstat(int fd,uint64 stat){
	//TODO: your job is to complete the syscall
	if (fd < 0 || fd >= FD_BUFFER_SIZE)
        return -1;
    struct proc *p = curr_proc();
    struct file *f = p->files[fd];
    if (f == NULL)
        return -1;
    return filestat(f, stat);
}

int sys_linkat(int olddirfd, uint64 oldpath, int newdirfd, uint64 newpath, uint64 flags){
	//TODO: your job is to complete the syscall
	struct proc *p = curr_proc();
    char old[MAXPATH], new[MAXPATH];
    copyinstr(p->pagetable, old, oldpath, MAXPATH);
    copyinstr(p->pagetable, new, newpath, MAXPATH);

    struct inode *ip = namei(old);
    if (ip == 0)
        return -1;
    ivalid(ip);

    // Disallow linking with the same name
    if (strncmp(old, new, MAXPATH) == 0) {
        iput(ip);
        return -1;
    }

    struct inode *dp = root_dir();
    ivalid(dp);

    ip->nlink++;
    iupdate(ip);

    if (dirlink(dp, new, ip->inum) < 0) {
        ip->nlink--;
        iupdate(ip);
        iput(dp);
        iput(ip);
        return -1;
    }

    iput(dp);
    iput(ip);
    return 0;
}

int sys_unlinkat(int dirfd, uint64 name, uint64 flags){
	//TODO: your job is to complete the syscall
	struct proc *p = curr_proc();
    char path[MAXPATH];
    copyinstr(p->pagetable, path, name, MAXPATH);

    struct inode *ip = namei(path);
    if (ip == 0)
        return -1;
    ivalid(ip);

    struct inode *dp = root_dir();
    ivalid(dp);

    if (dirunlink(dp, path) < 0) {
        iput(dp);
        iput(ip);
        return -1;
    }

    ip->nlink--;
    iupdate(ip);

    iput(dp);
    iput(ip);   // triggers free if nlink == 0 && ref drops to 0
    return 0;
}

extern char trap_page[];

void syscall()
{
	struct trapframe *trapframe = curr_proc()->trapframe;
	int id = trapframe->a7, ret;
	uint64 args[6] = { trapframe->a0, trapframe->a1, trapframe->a2,
			   trapframe->a3, trapframe->a4, trapframe->a5 };
	tracef("syscall %d args = [%x, %x, %x, %x, %x, %x]", id, args[0],
	       args[1], args[2], args[3], args[4], args[5]);
	switch (id) {
	case SYS_write:
		ret = sys_write(args[0], args[1], args[2]);
		break;
	case SYS_read:
		ret = sys_read(args[0], args[1], args[2]);
		break;
	case SYS_openat:
		ret = sys_openat(args[0], args[1], args[2]);
		break;
	case SYS_close:
		ret = sys_close(args[0]);
		break;
	case SYS_exit:
		sys_exit(args[0]);
		// __builtin_unreachable();
	case SYS_sched_yield:
		ret = sys_sched_yield();
		break;
	case SYS_gettimeofday:
		ret = sys_gettimeofday(args[0], args[1]);
		break;
	case SYS_getpid:
		ret = sys_getpid();
		break;
	case SYS_getppid:
		ret = sys_getppid();
		break;
	case SYS_clone: // SYS_fork
		ret = sys_clone();
		break;
	case SYS_execve:
		ret = sys_exec(args[0], args[1]);
		break;
	case SYS_wait4:
		ret = sys_wait(args[0], args[1]);
		break;
	case SYS_fstat:
	    ret = sys_fstat(args[0],args[1]);
		break;
	case SYS_linkat:
	    ret = sys_linkat(args[0],args[1],args[2],args[3],args[4]);
		break;
	case SYS_unlinkat:
	    ret = sys_unlinkat(args[0],args[1],args[2]);
		break;
	case SYS_spawn:
		ret = sys_spawn(args[0]);
		break;
	default:
		ret = -1;
		errorf("unknown syscall %d", id);
	}
	trapframe->a0 = ret;
	tracef("syscall ret %d", ret);
}
