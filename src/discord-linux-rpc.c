#include <ctype.h>
#include <errno.h>
#include <dirent.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/epoll.h>
#include <sys/prctl.h>
#include <sys/socket.h>

#include <linux/cn_proc.h>
#include <linux/connector.h>
#include <linux/netlink.h>

#include <systemd/sd-daemon.h>

#include <discord_rpc.h>

char *strdup0(const char *s) {
  return s ? strdup(s) : NULL;
}

int startswith(const char *s, const char *b) {
  return strncmp(s, b, strlen(b)) == 0;
}

int endswith(const char *s, const char *e) {
  size_t sl = strlen(s), el = strlen(e);
  if (sl != el) {
    return 0;
  }

  return memcmp(s + (sl - el), e, el) == 0;
}

int steali(int *p) {
  int v = *p;
  *p = -1;
  return v;
}

void *stealp(void *p) {
  void **pp = p;
  void *r = *pp;
  *pp = NULL;
  return r;
}

#define cleanup(func) __attribute__((__cleanup__(func)))

void closep(int *p) {
  if (*p != -1) {
    close(steali(p));
  }
}

void freep(void *p) {
  if (*(void **)p) {
    free(stealp(p));
  }
}

void fclosep(FILE **p) {
  if (*p) {
    fclose(stealp(p));
  }
}

void closedirp(DIR **p) {
  if (*p) {
    closedir(stealp(p));
  }
}

void logv(const char *prefix, const char *fmt, va_list args) {
  fputs(prefix, stderr);
  vfprintf(stderr, fmt, args);
}

__attribute__((format(printf, 1, 2))) void log_info(const char *fmt, ...) {
  va_list args;
  va_start(args, fmt);

  logv(SD_INFO, fmt, args);
  fputc('\n', stderr);

  va_end(args);
}

__attribute__((format(printf, 1, 2))) void log_error(const char *fmt, ...) {
  va_list args;
  va_start(args, fmt);

  logv(SD_ERR, fmt, args);
  fputc('\n', stderr);

  va_end(args);
}

__attribute__((format(printf, 2, 3))) void log_errno(int errno_, const char *fmt, ...) {
  va_list args;
  va_start(args, fmt);

  logv(SD_ERR, fmt, args);
  fprintf(stderr, ": %s\n", strerror(errno_));

  va_end(args);
}

typedef enum ConfigMatchType ConfigMatchType;
typedef struct ConfigEntry ConfigEntry;
typedef struct ActiveProcess ActiveProcess;

struct ConfigEntry {
  enum {
    CONFIG_NULL,
    CONFIG_MATCH_NAME,
    CONFIG_MATCH_PATH,
  } type;
  char *client_id;
  char *match;
  char *state;
};

struct ActiveProcess {
  pid_t pid;
  char *path;
  char *name;
  int64_t start;
  char *client_id;
  char *state;
};

ConfigEntry *g_config = NULL;
ActiveProcess g_active = {-1, NULL, NULL, -1, NULL, NULL};

int64_t g_boot_time = -1;

sig_atomic_t g_is_done = 0, g_discord_events_waiting = 0;

void on_signal(int sig) {
  switch (sig) {
  case SIGTERM:
  case SIGINT:
    g_is_done = 1;
    break;
  case SIGUSR1:
    g_discord_events_waiting = 1;
    break;
  default:
    log_error("on_signal(%d) unexpected", sig);
    break;
  }
}

int setup_sigterm_handler(sigset_t *orig_mask) {
  struct sigaction action;
  bzero(&action, sizeof(action));
  action.sa_handler = on_signal;

  if (sigaction(SIGTERM, &action, NULL) == -1) {
    log_errno(errno, "sigaction(SIGTERM)");
    return -1;
  }

  if (sigaction(SIGINT, &action, NULL) == -1) {
    log_errno(errno, "sigaction(SIGINT)");
    return -1;
  }

  if (sigaction(SIGUSR1, &action, NULL) == -1) {
    log_errno(errno, "sigaction(SIGUSR1)");
    return -1;
  }

  sigset_t mask;
  sigemptyset(&mask);
  sigaddset(&mask, SIGTERM);
  sigaddset(&mask, SIGINT);
  sigaddset(&mask, SIGUSR1);

  if (sigprocmask(SIG_BLOCK, &mask, orig_mask) == -1) {
    log_errno(errno, "sigprocmask(SIG_BLOCK, {SIGTERM, SIGUSR1})");
    return -1;
  }

  return 0;
}

int netlink_init() {
  pid_t pid = getpid();

  cleanup(closep) int nlfd = socket(PF_NETLINK, SOCK_DGRAM, NETLINK_CONNECTOR);
  if (nlfd == -1) {
    log_errno(errno, "socket(PF_NETLINK)");
    return -1;
  }

  struct sockaddr_nl nl_addr = {0};
  nl_addr.nl_family = AF_NETLINK;
  nl_addr.nl_groups = CN_IDX_PROC;
  nl_addr.nl_pid = pid;

  if (bind(nlfd, (struct sockaddr *)&nl_addr, sizeof(nl_addr)) == -1) {
    log_errno(errno, "bind(AF_NETLINK)");
    return -1;
  }

  #define NLMSG_SEND_LENGTH NLMSG_LENGTH(sizeof(struct cn_msg) + sizeof(enum proc_cn_mcast_op))
  #define NLMSG_RECV_LENGTH NLMSG_LENGTH(sizeof(struct cn_msg) + sizeof(struct proc_event))

  char buf[NLMSG_SPACE(NLMSG_SEND_LENGTH)] = {0};
  struct nlmsghdr *hdr = (struct nlmsghdr *)buf;
  hdr->nlmsg_len = NLMSG_SEND_LENGTH;
  hdr->nlmsg_type = NLMSG_DONE;
  hdr->nlmsg_pid = pid;

  struct cn_msg *msg = (struct cn_msg *)NLMSG_DATA(hdr);
  msg->id.idx = CN_IDX_PROC;
  msg->id.val = CN_VAL_PROC;

  enum proc_cn_mcast_op *op = (enum proc_cn_mcast_op *)msg->data;
  *op = PROC_CN_MCAST_LISTEN;
  msg->len = sizeof(enum proc_cn_mcast_op);

  if (send(nlfd, hdr, hdr->nlmsg_len, 0) == -1) {
    log_errno(errno, "send(nlfd)");
    return -1;
  }

  return steali(&nlfd);
}

int epoll_init(int nlfd) {
  cleanup(closep) int epfd = epoll_create1(0);
  if (epfd == -1) {
    log_errno(errno, "epoll_create1");
    return -1;
  }

  struct epoll_event ev;
  ev.events = EPOLLIN;
  ev.data.fd = nlfd;
  if (epoll_ctl(epfd, EPOLL_CTL_ADD, nlfd, &ev)) {
    log_errno(errno, "epoll_ctl(EPOLL_CTL_ADD)");
    return -1;
  }

  return steali(&epfd);
}

char *skip_ws(char *s) {
  for (; *s && isspace(*s); s++);
  return s;
}

void rchomp(char *s) {
  size_t len = strlen(s);
  for (char *p = s + len - 1; p != s && isspace(*p); p--) {
    *p = '\0';
  }
}

int load_config() {
  char *config_home = getenv("XDG_CONFIG_HOME");

  cleanup(closep) int homefd = -1;
  if (config_home == NULL) {
    homefd = openat(-1, getenv("HOME"), O_RDONLY|O_DIRECTORY);
    if (homefd == -1) {
      log_errno(errno, "openat(${HOME})");
      return -1;
    }

    config_home = ".config";
  }

  cleanup(closep) int root_configfd = openat(homefd, config_home, O_RDONLY|O_DIRECTORY);
  if (root_configfd == -1) {
    log_errno(errno, "openat(${XDG_CONFIG_HOME})");
    return -1;
  }

  cleanup(closep) int dir_configfd = openat(root_configfd, "discord-linux-rpc",
                                            O_RDONLY|O_DIRECTORY);
  if (dir_configfd == -1) {
    log_errno(errno, "openat(${XDG_CONFIG_HOME}/discord-linux-rpc)");
    return -1;
  }

  cleanup(closep) int configfd = openat(dir_configfd, "proc", O_RDONLY);
  if (configfd == -1) {
    log_errno(errno, "openat(${XDG_CONFIG_HOME}/discord-linux-rpc/proc)");
    return -1;
  }

  cleanup(fclosep) FILE *fp = fdopen(configfd, "r");
  if (fp == NULL) {
    log_errno(errno, "fdopen(${XDG_CONFIG_HOME}/discord-linux-rpc/proc)");
    return -1;
  }
  steali(&configfd);

  int entries = 0;

  for (;;) {
    cleanup(freep) char *line = NULL;
    char *p = NULL, *type, *match = NULL, *state = NULL;
    size_t len = 0;

    if (getline(&line, &len, fp) == -1) {
      if (feof(fp)) {
        break;
      } else {
        log_errno(errno, "getline(config)");
        return -1;
      }
    }

    p = skip_ws(line);
    if (*p == '\0') {
      continue;
    }

    ConfigEntry *new_config = realloc(g_config, (entries + 2) * sizeof(ConfigEntry));
    if (new_config == NULL) {
      return -1;
    }

    ConfigEntry *current = &new_config[entries];
    bzero(current, sizeof(ConfigEntry) * 2);
    g_config = new_config;

    type = strstr(p, " ");
    if (!type) {
      goto invalid_line;
    }

    *type = '\0';
    type = skip_ws(type + 1);
    if (*type == '\0') {
      goto invalid_line;
    }

    match = strstr(type, " ");
    if (!match) {
      goto invalid_line;
    }

    *match = '\0';
    match = skip_ws(match + 1);
    if (*match == '\0') {
      goto invalid_line;
    }

    state = strstr(match, " -- ");
    if (state) {
      *state = '\0';
      state = skip_ws(state + 4);
      if (*state == '\0') {
        goto invalid_line;
      }
    }

    if (strcmp(type, "name") == 0) {
      current->type = CONFIG_MATCH_NAME;
    } else if (strcmp(type, "path") == 0) {
      current->type = CONFIG_MATCH_PATH;
    } else {
      goto invalid_line;
    }

    p = skip_ws(p + 5);
    if (*p == '\0') {
      goto invalid_line;
    }

    rchomp(line);
    rchomp(p);
    rchomp(match);

    current->client_id = strdup(p);
    current->match = strdup(match);
    current->state = strdup0(state);

    entries++;

    continue;

invalid_line:
    log_error("Invalid line in config: %s", line);
    return -1;
  }

  return 0;
}

void free_config() {
  if (g_config == NULL) {
    return;
  }

  for (ConfigEntry *entry = g_config; entry->type != CONFIG_NULL; entry++) {
    free(entry->match);
    free(entry->state);
  }

  free(stealp(&g_config));
}

void free_active_process() {
  if (g_active.pid == -1) {
    return;
  }

  g_active.pid = -1;
  free(stealp(&g_active.path));
  free(stealp(&g_active.name));
  free(stealp(&g_active.state));
}

void update_discord_presence() {
  if (g_active.pid != -1) {
    log_info("update_discord_presence: %u:%s(%s)", g_active.pid, g_active.path, g_active.name);
    Discord_Shutdown();

    Discord_Initialize(g_active.client_id, NULL, 0, NULL);

    DiscordRichPresence rp = {0};
    rp.state = g_active.state;
    rp.startTimestamp = g_boot_time + g_active.start;
    Discord_UpdatePresence(&rp);
  } else {
    puts("update_discord_presence: clear active");
    Discord_Shutdown();
  }
}

int read_boot_time(int procfd) {
  cleanup(closep) int statfd = openat(procfd, "stat", O_RDONLY);
  if (statfd == -1) {
    log_errno(errno, "openat(/proc/stat)");
    return -1;
  }

  cleanup(fclosep) FILE *fp = fdopen(statfd, "r");
  if (fp == NULL) {
    log_errno(errno, "fdopen(/proc/stat)");
    return -1;
  }
  steali(&statfd);

  for (;;) {
    cleanup(freep) char *line = NULL;
    size_t len = 0;

    if (getline(&line, &len, fp) == -1) {
      if (feof(fp)) {
        break;
      } else {
        log_errno(errno, "getline(/proc/stat)");
        return -1;
      }
    }

    if (startswith(line, "btime ")) {
      g_boot_time = strtoll(line + 5, NULL, 10);
      return 0;
    }
  }

  return -1;
}

void read_process_info(const char *pid, int pidfd, char **path, char **name, int64_t *start) {
  char linkbuf[PATH_MAX];
  ssize_t written = readlinkat(pidfd, "exe", linkbuf, sizeof(linkbuf) - 1);
  if (written == -1) {
    if (errno != ENOENT && errno != EACCES) {
      log_errno(errno, "readlinkat(procfd/%s/exe)", pid);
    }
    goto after_link;
  }

  linkbuf[written] = '\0';
  *path = strdup(linkbuf);

after_link: ;

  cleanup(closep) int cmdfd = -1;
  cleanup(fclosep) FILE *cmdfp = NULL;

  cmdfd = openat(pidfd, "cmdline", O_RDONLY);
  if (cmdfd == -1) {
    log_errno(errno, "openat(procfd/%s/cmdline)", pid);
    goto after_name;
  }

  cmdfp = fdopen(cmdfd, "r");
  if (cmdfp == NULL) {
    log_errno(errno, "fdopen(procfd/%s/cmdline)", pid);
    goto after_name;
  }
  steali(&cmdfd);

  size_t len;
  if (getdelim(name, &len, '\0', cmdfp) == -1) {
    if (errno != ENOENT && errno != EACCES) {
      log_errno(errno, "getdelim(procfd/%s/cmdline)", pid);
    }
    free(stealp(name));
    goto after_name;
  }

after_name: ;

  cleanup(closep) int statfd = -1;
  cleanup(fclosep) FILE *statfp = NULL;
  cleanup(freep) char *starttime_s = NULL;\
  uint64_t starttime = 0;

  statfd = openat(pidfd, "stat", O_RDONLY);
  if (statfd == -1) {
    log_errno(errno, "openat(procfd/%s/stat)", pid);
    goto after_stat;
  }

  statfp = fdopen(statfd, "r");
  if (statfp == NULL) {
    log_errno(errno, "fdopen(procfd/%s/stat)", pid);
    goto after_stat;
  }
  steali(&statfd);

  for (int i = 0; i < 22; i++) {
    cleanup(freep) char *part = NULL;
    if (getdelim(&part, &len, ' ', statfp) == -1) {
      log_errno(errno, "getdelim(procfd/%s/stat)", pid);
      goto after_stat;
    }

    if (i == 21) {
      // Last item is starttime
      starttime_s = stealp(&part);
    }
  }

  starttime = strtoull(starttime_s, NULL, 10);
  *start = starttime / sysconf(_SC_CLK_TCK);

after_stat: ;

  return;
}

ConfigEntry * find_matching_entry(const char *path, const char *name, ConfigEntry *stop_at) {
  for (ConfigEntry *entry = g_config; entry->type != CONFIG_NULL; entry++) {
    if (entry == stop_at) {
      return NULL;
    }

    switch (entry->type) {
    case CONFIG_NULL: abort();
    case CONFIG_MATCH_PATH:
      if (path == NULL) {
        continue;
      }

      if (entry->match[0] == '/') {
        if (strcmp(path, entry->match) == 0) {
          return entry;
        }
      } else {
        if (endswith(path, entry->match)) {
          return entry;
        }
      }
      break;
    case CONFIG_MATCH_NAME:
      if (name == NULL) {
        continue;
      }

      if (strcmp(entry->match, name) == 0) {
        return entry;
      }
      break;
    }
  }

  return NULL;
}

ConfigEntry * try_set_active_process_pidstr(int procfd, const char *pid, ConfigEntry *stop_at) {
  cleanup(closep) int pidfd = openat(procfd, pid, O_DIRECTORY|O_RDONLY);
  if (pidfd == -1) {
    if (errno != ENOENT) {
      log_errno(errno, "openat(procfd/%s)", pid);
    }
    return NULL;
  }

  cleanup(freep) char *path = NULL;
  cleanup(freep) char *name = NULL;
  int64_t start = -1;
  read_process_info(pid, pidfd, &path, &name, &start);

  if (path == NULL && name == NULL) {
    return NULL;
  }

  ConfigEntry *entry = find_matching_entry(path, name, stop_at);
  if (entry != NULL) {
    g_active.pid = strtol(pid, NULL, 10);
    g_active.path = stealp(&path);
    g_active.name = stealp(&name);
    g_active.start = start;
    g_active.client_id = strdup(entry->client_id);
    g_active.state = strdup0(entry->state);
    log_info("Set active process to %u:%s(%s)", g_active.pid, g_active.path, g_active.name);
    return entry;
  }

  return NULL;
}

ConfigEntry * try_set_active_process_pid(int procfd, pid_t pid, ConfigEntry *stop_at) {
  char pidbuf[16];
  snprintf(pidbuf, sizeof(pidbuf), "%u", pid);

  return try_set_active_process_pidstr(procfd, pidbuf, stop_at);
}

void find_active_process(int procfd) {
  /* cleanup(closep) int procfd2 = dup(procfd); */
  /* if (procfd2 == -1) { */
  /*   log_errno(errno, "dup(procfd)"); */
  /*   return; */
  /* } */

  /* XXX: fdopendir will cause /proc to always be empty, even when dup'd */
  /* cleanup(closedirp) DIR *dir = fdopendir(procfd2); */
  cleanup(closedirp) DIR *dir = opendir("/proc");
  if (dir == NULL) {
    log_errno(errno, "fdopendir(/proc)");
    return;
  }
  /* steali(&procfd2); */

  ConfigEntry *active = NULL;
  if (g_active.pid != -1) {
    active = find_matching_entry(g_active.path, g_active.name, NULL);
  }

  for (;;) {
    errno = 0;
    struct dirent *entry = readdir(dir);
    if (entry == NULL) {
      if (errno) {
        log_errno(errno, "readdir(/proc)");
      }
      break;
    }

    int all_digits = 1;
    for (char *p = entry->d_name; *p != '\0'; p++) {
      if (!isdigit(*p)) {
        all_digits = 0;
      }
    }

    if (!all_digits) {
      continue;
    }

    ConfigEntry *new_active = try_set_active_process_pidstr(procfd, entry->d_name, active);
    if (new_active != NULL) {
      active = new_active;
    }
  }
}

void handle_process_event(int procfd, struct proc_event *proc) {
  if (proc->what == PROC_EVENT_EXEC) {
    ConfigEntry *active = NULL;
    pid_t orig_pid = g_active.pid;
    if (orig_pid != -1) {
      active = find_matching_entry(g_active.path, g_active.name, NULL);
    }

    try_set_active_process_pid(procfd, proc->event_data.exec.process_pid, active);

    if (orig_pid != g_active.pid) {
      update_discord_presence();
    }
  } else if (proc->what == PROC_EVENT_EXIT &&
             proc->event_data.exit.process_pid == g_active.pid) {
    free_active_process();
    find_active_process(procfd);

    update_discord_presence();
  }
}

int handle_events(int nlfd, int epfd, sigset_t *orig_mask) {
  #define EPOLL_EVENT_COUNT 16
  struct epoll_event events[EPOLL_EVENT_COUNT];
  char buf[NLMSG_SPACE(NLMSG_RECV_LENGTH)] = {0};
  struct nlmsghdr *hdr = (struct nlmsghdr *)buf;

  cleanup(closep) int procfd = openat(-1, "/proc", O_DIRECTORY|O_RDONLY);
  if (procfd == -1) {
    log_errno(errno, "openat(/proc)");
    return -1;
  }

  if (read_boot_time(procfd) == -1) {
    return -1;
  }

  find_active_process(procfd);
  update_discord_presence();

  for (;;) {
    int nev = epoll_pwait(epfd, events, EPOLL_EVENT_COUNT, -1, orig_mask);
    if (nev == -1) {
      if (errno == EINTR) {
        if (g_is_done) {
          return 0;
        } else if (g_discord_events_waiting) {
          Discord_RunCallbacks();
        }
      } else {
        log_errno(errno, "epoll_pwait");
      }

      continue;
    }

    for (int i = 0; i < nev; i++) {
      if (events[i].data.fd == nlfd) {
        if (recv(nlfd, buf, sizeof(buf), MSG_DONTWAIT) == -1) {
          if (errno != EAGAIN && errno != EWOULDBLOCK) {
            log_errno(errno, "recv");
          }

          continue;
        }

        if (hdr->nlmsg_type == NLMSG_DONE) {
          struct proc_event *proc = (struct proc_event *)((struct cn_msg *)NLMSG_DATA(hdr))->data;
          if (proc->what == PROC_EVENT_EXEC || proc->what == PROC_EVENT_EXIT) {
            handle_process_event(procfd, proc);
          }
        }
      }
    }
  }
}

int main(int argc, char **argv, char **envp) {
  sigset_t orig_mask;
  if (setup_sigterm_handler(&orig_mask) == -1) {
    return 1;
  }

  cleanup(closep) int nlfd = netlink_init();
  if (nlfd == -1) {
    return 1;
  }

  cleanup(closep) int epfd = epoll_init(nlfd);
  if (epfd == -1) {
    return 1;
  }

  if (load_config() == -1) {
    free_config();
    return 1;
  }

  int rc = handle_events(nlfd, epfd, &orig_mask);

  free_active_process();
  free_config();
  update_discord_presence();

  return -rc;
}
