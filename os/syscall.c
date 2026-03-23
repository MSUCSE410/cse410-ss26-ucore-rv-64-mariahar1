#include "syscall.h"
#include "defs.h"
#include "loader.h"
#include "syscall_ids.h"
#include "timer.h"
#include "trap.h"
#include "proc.h"

uint64 sys_write(int fd, uint64 va, uint len)
{
	debugf("sys_write fd = %d va = %x, len = %d", fd, va, len);
	if (fd != STDOUT)
		return -1;
	struct proc *p = curr_proc();
	char str[MAX_STR_LEN];
	int size = copyinstr(p->pagetable, str, va, MIN(len, MAX_STR_LEN));
	debugf("size = %d", size);
	for (int i = 0; i < size; ++i) {
		console_putchar(str[i]);
	}
	return size;
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

uint64 sys_gettimeofday(TimeVal *val, int _tz) 
{
	// YOUR CODE

	/* The code in `ch3` will leads to memory bugs*/

	// uint64 cycle = get_cycle();
	// val->sec = cycle / CPU_FREQ;
	// val->usec = (cycle % CPU_FREQ) * 1000000 / CPU_FREQ;


	if (!val) {
		return -1;
	}
	TimeVal curr_val; //temporary timeval so we dont disturb the original val

	uint64 cycle = get_cycle();
	curr_val.sec = cycle / CPU_FREQ;
	curr_val.usec = (cycle % CPU_FREQ) * 1000000UL / CPU_FREQ;

	//writing to pagetable, return -1 if fail
	if (copyout(curr_proc()->pagetable, (uint64)val, (char *)&curr_val, sizeof(curr_val)) < 0) {
		return -1;
	}

	return 0;
}


uint64 sys_task_info(struct TaskInfo *ti) {
    struct proc *p = curr_proc();

	if (!ti) {
		return -1;
	}

	struct TaskInfo temp_ti; // temporary task info so we dont disturb the original ti

	//running
    temp_ti.status = Running;

	// getting syscall tume from kernal
    for (int i = 0; i < MAX_SYSCALL_NUM; i++) {
        temp_ti.syscall_times[i] = p->syscall_times[i];
    }

    temp_ti.time = (int)((get_cycle() - p->start_time) / (CPU_FREQ / 1000)); // time calc

	if (copyout(p->pagetable, (uint64)ti, (char *)&temp_ti, sizeof(struct TaskInfo)) < 0) {
		return -1;
	}

    return 0;
}

// TODO: add support for mmap and munmap syscall.
// hint: read through docstrings in vm.c. Watching CH4 video may also help.
// Note the return value and PTE flags (especially U,X,W,R)
/*
* LAB1: you may need to define sys_task_info here
*/


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

extern char trap_page[];

void syscall()
{
	struct trapframe *trapframe = curr_proc()->trapframe;
	int id = trapframe->a7, ret;
	uint64 args[6] = { trapframe->a0, trapframe->a1, trapframe->a2,
			   trapframe->a3, trapframe->a4, trapframe->a5 };
	tracef("syscall %d args = [%x, %x, %x, %x, %x, %x]", id, args[0],
	       args[1], args[2], args[3], args[4], args[5]);
	/*
	* LAB1: you may need to update syscall counter for task info here
	*/
	if (id >= 0 && id < MAX_SYSCALL_NUM) {
    	curr_proc()->syscall_times[id]++;
	}

	switch (id) {
	case SYS_write:
		ret = sys_write(args[0], args[1], args[2]);
		break;
	case SYS_exit:
		sys_exit(args[0]);
		// __builtin_unreachable();
	case SYS_sched_yield:
		ret = sys_sched_yield();
		break;
	case SYS_gettimeofday:
		ret = sys_gettimeofday((TimeVal *)args[0], args[1]);
		break;
	/*
	* LAB1: you may need to add SYS_taskinfo case here
	*/
	case SYS_task_info:
        ret = sys_task_info((struct TaskInfo *)args[0]);
        break;
	case SYS_mmap:
		ret = sys_mmap((void *)args[0], (unsigned long long)args[1], (int)args[2], (int)args[3], (int)args[4]);
		break;
	case SYS_munmap:
		ret = sys_munmap((void *)args[0], (unsigned long long)args[1]);
		break;
	default:
		ret = -1;
		errorf("unknown syscall %d", id);
	}
	trapframe->a0 = ret;
	tracef("syscall ret %d", ret);
}
