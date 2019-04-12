/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

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

#include <sys/socket.h>
#include <sys/un.h>

#include <systemd/sd-daemon.h>
#include <systemd/sd-event.h>

/* #include <yajl/yajl_parse.h> */
#include <yajl/yajl_gen.h>

#include <prkit.h>

#define DISCORD_MAX_RPC_FRAME_SIZE (64 * 1024)

typedef unsigned char uchar;

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

void yajl_gen_freep(yajl_gen *p) {
  if (*p) {
    yajl_gen_free(stealp(p));
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

  sd_notifyf(0, "ERRNO=%d", errno_);
}

__attribute__((format(printf, 2, 3))) void log_yajl_gen(yajl_gen_status status, const char *fmt,
                                                        ...) {
  va_list args;
  va_start(args, fmt);

  logv(SD_ERR, fmt, args);

  fputs(":", stderr);

  switch (status) {
  case yajl_gen_status_ok: fputs("OK\n", stderr); break;
  case yajl_gen_keys_must_be_strings: fputs("Keys must be strings\n", stderr); break;
  case yajl_max_depth_exceeded: fputs("Max depth exceeded\n", stderr); break;
  case yajl_gen_in_error_state: fputs("Already in error state\n", stderr); break;
  case yajl_gen_generation_complete: fputs("Generation complete\n", stderr); break;
  case yajl_gen_invalid_number: fputs("Invalid number\n", stderr); break;
  case yajl_gen_no_buf: fputs("No buffer\n", stderr); break;
  case yajl_gen_invalid_string: fputs("Invalid utf-8 string\n", stderr); break;
  }

  va_end(args);
}

typedef enum ConfigMatchType ConfigMatchType;
typedef struct ConfigEntry ConfigEntry;
typedef struct ActiveProcess ActiveProcess;
typedef struct Context Context;
typedef struct RpcHeader RpcHeader;
typedef struct RpcMessage RpcMessage;

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

struct Context {
  int procfd;
  int rpcfd;
  enum {
    RPC_DISCONNECTED,
    RPC_WAITING_RECONNECT,
    RPC_AUTH_PRE,
    RPC_AUTH_WAIT,
    RPC_READY,
  } rpcstate;
  char *rpc_client_id;
  unsigned long rpc_nonce;
  ConfigEntry *config;
  ActiveProcess active;
  int64_t boot_time;
};

struct RpcHeader {
  enum {
    RPC_OP_HANDSHAKE = 0,
    RPC_OP_FRAME = 1,
    RPC_OP_CLOSE = 2,
    RPC_OP_PING = 3,
    RPC_OP_PONG = 4,
  } op;
  uint32_t len;
};

struct RpcMessage {
  RpcHeader hdr;
  char data[DISCORD_MAX_RPC_FRAME_SIZE - sizeof(RpcHeader)];
};

int config_load(Context *ctx) {
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

    rchomp(line);

    p = skip_ws(line);
    if (*p == '\0' || *p == '#') {
      continue;
    }

    ConfigEntry *new_config = realloc(ctx->config, (entries + 2) * sizeof(ConfigEntry));
    if (new_config == NULL) {
      return -1;
    }

    ConfigEntry *current = &new_config[entries];
    bzero(current, sizeof(ConfigEntry) * 2);
    ctx->config = new_config;

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

int64_t read_boot_time(int procfd) {
  struct prkit_kernel_stat kstat;
  int rc = prkit_kernel_stat(procfd, &kstat);
  if (rc < 0) {
    log_errno(-rc, "prkit_kernel_stat");
    return -1;
  }

  return kstat.fields & PRKIT_KERNEL_STAT_BTIME ? kstat.btime : -1;
}

int context_open(Context *ctx) {
  int rc = prkit_open(&ctx->procfd);
  if (rc < 0) {
    log_errno(-rc, "prkit_open");
    return -1;
  }

  ctx->rpcfd = -1;

  ctx->boot_time = read_boot_time(ctx->procfd);
  if (ctx->boot_time == -1) {
    return -1;
  }

  return 0;
}

void config_free(Context *ctx) {
  if (ctx->config == NULL) {
    return;
  }

  for (ConfigEntry *entry = ctx->config; entry->type != CONFIG_NULL; entry++) {
    free(entry->match);
    free(entry->state);
  }

  free(stealp(&ctx->config));
}

void active_process_free(Context *ctx) {
  if (ctx->active.pid == -1) {
    return;
  }

  ctx->active.pid = -1;
  free(stealp(&ctx->active.path));
  free(stealp(&ctx->active.name));
  free(stealp(&ctx->active.state));
}

void context_free(Context *ctx) {
  closep(&ctx->procfd);
  closep(&ctx->rpcfd);
  freep(&ctx->rpc_client_id);
  active_process_free(ctx);
  config_free(ctx);
}

int on_discord_reconnect_event(sd_event_source *s, uint64_t usec, void *ud);

void discord_schedule_reconnect(sd_event *event, Context *ctx) {
  if (ctx->rpcstate == RPC_WAITING_RECONNECT) {
    return;
  }

  struct timespec ts;
  if (clock_gettime(CLOCK_MONOTONIC, &ts) == -1) {
    log_errno(errno, "clock_gettime");
    return;
  }

  // Dispatch after a 5-second delay.
  ts.tv_sec += 5;
  uint64_t usec = ts.tv_sec * 1000000 + ts.tv_nsec / 1000;

  int rc = sd_event_add_time(event, NULL, CLOCK_MONOTONIC, usec, 60000000,
                             on_discord_reconnect_event, ctx);
  if (rc < 0) {
    log_errno(-rc, "sd_event_add_time");
    return;
  }

  log_info("rpc waiting reconnect");
  ctx->rpcstate = RPC_WAITING_RECONNECT;
}

void discord_update_presence(Context *ctx);

int on_discord_rpc_event(sd_event_source *s, int rpcfd, uint32_t revents, void *ud) {
  Context *ctx = ud;

  if (revents & (EPOLLERR | EPOLLHUP)) {
    // Force reconnect.
    log_info("rpc poll error, scheduling reconnect...");
    closep(&ctx->rpcfd);
    discord_schedule_reconnect(sd_event_source_get_event(s), ctx);
    return -1;
  }

  RpcMessage msg;
  bzero(&msg, sizeof(msg));

  if (recv(rpcfd, &msg.hdr, sizeof(msg.hdr), 0) < 0) {
    log_errno(errno, "recv on frame header");
    return 0;
  }

  if (msg.hdr.len != 0) {
    if (recv(rpcfd, msg.data, msg.hdr.len, 0) < 0) {
      log_errno(errno, "recv on frame message");
      return 0;
    }
  }

  switch (msg.hdr.op) {
  case RPC_OP_FRAME:
    // XXX
    if (ctx->rpcstate == RPC_AUTH_WAIT &&
        memmem(msg.data, msg.hdr.len, "READY", strlen("READY")) != NULL) {
      log_info("rpc ready");
      ctx->rpcstate = RPC_READY;

      discord_update_presence(ctx);
    } else {
      log_info("frame %*s", msg.hdr.len, msg.data);
    }
    break;
  case RPC_OP_PING:
    if (send(rpcfd, &msg, sizeof(msg.hdr) + msg.hdr.len, 0) < 0) {
      log_errno(errno, "send ping");
    }
    break;
  case RPC_OP_PONG:
    // Pong.
    break;
  default:
    log_error("Unknown RPC op code: %d", msg.hdr.op);
    // Fallthrough.
  case RPC_OP_HANDSHAKE:
  case RPC_OP_CLOSE:
    closep(&ctx->rpcfd);
    discord_schedule_reconnect(sd_event_source_get_event(s), ctx);
    return -1;
  }

  return 0;
}

int discord_send_handshake(Context *ctx) {
  cleanup(yajl_gen_freep) yajl_gen gen = yajl_gen_alloc(NULL);
  yajl_gen_status gs = yajl_gen_status_ok;

  const char *json = NULL;
  size_t json_len;
  if ((gs = yajl_gen_map_open(gen))
      || (gs = yajl_gen_string(gen, (const uchar *)"v", strlen("v")))
      || (gs = yajl_gen_integer(gen, 1))
      || (gs = yajl_gen_string(gen, (const uchar *)"client_id", strlen("client_id")))
      || (gs = yajl_gen_string(gen, (const uchar *)ctx->active.client_id,
                               strlen(ctx->active.client_id)))
      || (gs = yajl_gen_map_close(gen))
      || (gs = yajl_gen_get_buf(gen, (const uchar **)&json, &json_len))) {
    log_yajl_gen(gs, "handshake");
    return -1;
  }

  RpcMessage msg;
  msg.hdr.op = RPC_OP_HANDSHAKE;
  msg.hdr.len = json_len;
  strncpy(msg.data, json, sizeof(msg.data));

  if (send(ctx->rpcfd, &msg, sizeof(msg.hdr) + msg.hdr.len, 0) < 0) {
    log_errno(errno, "handshake send");
    return -1;
  }

  freep(&ctx->rpc_client_id);
  ctx->rpc_client_id = strdup(ctx->active.client_id);

  return 0;
}

void discord_update_connection(Context *ctx) {
  if (ctx->rpcfd != -1 && ctx->rpcstate > RPC_AUTH_PRE) {
    // We've already sent an auth handshake, so disconnect and reconnect.
    closep(&ctx->rpcfd);
  }

  ctx->rpcstate = RPC_DISCONNECTED;

  cleanup(sd_event_unrefp) sd_event *event = NULL;
  int rc = sd_event_default(&event);
  if (rc < 0) {
    log_errno(-rc, "sd_event_default");
    return;
  }

  if (ctx->rpcfd == -1) {
    cleanup(closep) int rpcfd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (rpcfd == -1) {
      log_errno(-errno, "discord_update_connection socket");
      return;
    }

    const char *xdg_runtime_dir = getenv("XDG_RUNTIME_DIR");

    for (int i = 0; i < 9; i++) {
      for (int j = 0; j < 2; j++) {
        struct sockaddr_un addr;
        bzero(&addr, sizeof(addr));
        addr.sun_family = AF_UNIX;

        if (j == 0) {
          snprintf(addr.sun_path, sizeof(addr.sun_path), "%s/discord-ipc-%d", xdg_runtime_dir, i);
        } else {
          snprintf(addr.sun_path, sizeof(addr.sun_path), "%s/discord/ipc-%d", xdg_runtime_dir, i);
        }

        if (connect(rpcfd, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
          if (errno != -ENOENT) {
            log_errno(errno, "bind %s", addr.sun_path);
          }

          continue;
        }

        // Add the fd to our event loop.
        rc = sd_event_add_io(event, NULL, rpcfd, EPOLLIN, on_discord_rpc_event, ctx);
        if (rc < 0) {
          log_errno(-rc, "sd_event_add_io(rpcfd)");
        }

        ctx->rpcfd = steali(&rpcfd);
        goto rpc_connected;
      }
    }

    // All failed, reschedule a connection attempt for later.
    discord_schedule_reconnect(event, ctx);
    return;
  }

  rpc_connected:

  if (ctx->active.pid == -1) {
    // We can't auth yet, wait until later to connect.
    log_info("rpc auth pre");
    ctx->rpcstate = RPC_AUTH_PRE;
    return;
  }

  // Send the handshake.
  if (discord_send_handshake(ctx) == -1) {
    return;
  }

  ctx->rpcstate = RPC_AUTH_WAIT;
}

int on_discord_reconnect_event(sd_event_source *s, uint64_t usec, void *ud) {
  Context *ctx = ud;
  if (ctx->rpcfd != -1) {
    // We're already connected by someone else.
    return 0;
  }

  discord_update_connection(ctx);

  return 0;
}

void discord_update_presence(Context *ctx) {
  if (ctx->rpcstate != RPC_READY || strcmp(ctx->active.client_id, ctx->rpc_client_id) != 0) {
    discord_update_connection(ctx);
    return;
  }

  cleanup(yajl_gen_freep) yajl_gen gen = yajl_gen_alloc(NULL);
  yajl_gen_status gs = yajl_gen_status_ok;

  char nonce[16];
  snprintf(nonce, sizeof(nonce), "%lu", ctx->rpc_nonce++);

  const char *state = ctx->active.state;
  pid_t pid = ctx->active.pid;
  if (pid < 10) {
    pid = getpid();
  }

  if ((gs = yajl_gen_map_open(gen))
      || (gs = yajl_gen_string(gen, (const uchar *)"cmd", strlen("cmd")))
      || (gs = yajl_gen_string(gen, (const uchar *)"SET_ACTIVITY", strlen("SET_ACTIVITY")))
      || (gs = yajl_gen_string(gen, (const uchar *)"nonce", strlen("nonce")))
      || (gs = yajl_gen_string(gen, (const uchar *)nonce, strlen(nonce)))
      || (gs = yajl_gen_string(gen, (const uchar *)"args", strlen("args")))
      || (gs = yajl_gen_map_open(gen))
      || (gs = yajl_gen_string(gen, (const uchar *)"pid", strlen("pid")))
      || (gs = yajl_gen_integer(gen, pid))) {
    log_yajl_gen(gs, "presence main object");
    return;
  }

  if (ctx->active.pid != -1) {
    log_info("discord_update_presence: %u:%s(%s)", ctx->active.pid, ctx->active.path,
             ctx->active.name);

    if ((gs = yajl_gen_string(gen, (const uchar *)"activity", strlen("activity")))
        || (gs = yajl_gen_map_open(gen))) {
      log_yajl_gen(gs, "presence activity object opening");
      return;
    }

    if (state != NULL) {
      if ((gs = yajl_gen_string(gen, (const uchar *)"state", strlen("state")))
          || (gs = yajl_gen_string(gen, (const uchar *)state, strlen(state)))) {
        log_yajl_gen(gs, "presence activity state");
        return;
      }
    }

    if ((gs = yajl_gen_string(gen, (const uchar *)"assets", strlen("assets")))
        || (gs = yajl_gen_map_open(gen))
        || (gs = yajl_gen_string(gen, (const uchar *)"large_image", strlen("large_image")))
        || (gs = yajl_gen_string(gen, (const uchar *)"discord-linux-rpc",
                                 strlen("discord-linux-rpc")))
        || (gs = yajl_gen_map_close(gen))
        || (gs = yajl_gen_string(gen, (const uchar *)"timestamps", strlen("timestamps")))
        || (gs = yajl_gen_map_open(gen))
        || (gs = yajl_gen_string(gen, (const uchar *)"start", strlen("start")))
        || (gs = yajl_gen_integer(gen, ctx->boot_time + ctx->active.start))
        || (gs = yajl_gen_map_close(gen))
        || (gs = yajl_gen_map_close(gen))) {
      log_yajl_gen(gs, "presence activity");
      return;
    }
  } else {
    log_info("discord_update_presence: clear active");
  }

  const char *json;
  size_t json_len;

  if ((gs = yajl_gen_map_close(gen))
      || (gs = yajl_gen_map_close(gen))
      || (gs = yajl_gen_get_buf(gen, (const uchar **)&json, &json_len))) {
    log_yajl_gen(gs, "presence finish");
    return;
  }

  RpcMessage msg;
  msg.hdr.op = RPC_OP_FRAME;
  msg.hdr.len = json_len;
  strncpy(msg.data, json, sizeof(msg.data));

  if (send(ctx->rpcfd, &msg, sizeof(msg.hdr) + msg.hdr.len, 0) < 0) {
    log_errno(errno, "presence send");
  }
}

void read_process_info(int pid, int pidfd, char **path, char **name, int64_t *start) {
  cleanup(freep) char *exe = NULL;
  int rc = 0;

  rc = prkit_pid_resolve_exe(pidfd, &exe, NULL);
  if (rc < 0) {
    if (rc != -ENOENT && rc != -EACCES) {
      log_errno(-rc, "prkit_pid_resolve_exe(%d)", pid);
    }
    goto after_link;
  }

  *path = stealp(&exe);

after_link: ;

  cleanup(prkit_free_strvp) char **cmdline_strv = NULL;
  rc = prkit_pid_cmdline_strv(pidfd, &cmdline_strv);
  if (rc < 0) {
    if (-rc != -ENOENT && -rc != -EACCES) {
      log_errno(-rc, "prkit_pid_cmdline_strv(%d)", pid);
    }
    goto after_name;
  }

  *name = strdup0(cmdline_strv[0]);

after_name: ;

  struct prkit_pid_stat pstat;
  rc = prkit_pid_stat(pidfd, &pstat);
  if (rc < 0) {
    log_errno(-rc, "prkit_pid_stat(%d)", pid);
    goto after_stat;
  }

  *start = pstat.starttime / sysconf(_SC_CLK_TCK);

after_stat: ;

  return;
}

ConfigEntry * find_matching_entry(ConfigEntry *entry, const char *path, const char *name,
                                  ConfigEntry *stop_at) {
  for (; entry->type != CONFIG_NULL; entry++) {
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

ConfigEntry * try_set_active_process_pid(Context *ctx, int pid, ConfigEntry *stop_at) {
  cleanup(closep) int pidfd = -1;
  int rc = prkit_pid_open(ctx->procfd, pid, &pidfd);
  if (rc < 0) {
    if (rc != -ENOENT) {
      log_errno(-rc, "prkit_open(%d)", pid);
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

  ConfigEntry *entry = find_matching_entry(ctx->config, path, name, stop_at);
  if (entry != NULL) {
    ctx->active.pid = pid;
    ctx->active.path = stealp(&path);
    ctx->active.name = stealp(&name);
    ctx->active.start = start;
    ctx->active.client_id = strdup(entry->client_id);
    ctx->active.state = strdup0(entry->state);
    log_info("Set active process to %u:%s(%s)", ctx->active.pid, ctx->active.path,
             ctx->active.name);
    return entry;
  }

  return NULL;
}

void active_process_find(Context *ctx) {
  ConfigEntry *active = NULL;
  if (ctx->active.pid != -1) {
    active = find_matching_entry(ctx->config, ctx->active.path, ctx->active.name, NULL);
  }

  int rc = prkit_walk_reset(ctx->procfd);
  if (rc < 0) {
    log_errno(-rc, "prkit_walk_reset");
    return;
  }

  int pids[32];
  for (;;) {
    size_t count = sizeof(pids) / sizeof(pids[0]);
    rc = prkit_walk_read(ctx->procfd, pids, &count);
    if (rc < 0) {
      log_errno(-rc, "prkit_walk_read");
      break;
    } else if (count == 0) {
      break;
    }

    for (int i = 0; i < count; i++) {
      ConfigEntry *new_active = try_set_active_process_pid(ctx, pids[i], active);
      if (new_active != NULL) {
        active = new_active;
      }
    }
  }
}

int on_config_reload_request(sd_event_source *s, const struct signalfd_siginfo *si, void *ud) {
  Context *ctx = ud;
  sd_notify(0, "RELOADING=1");
  config_free(ctx);

  if (config_load(ctx) == -1) {
    config_free(ctx);
    active_process_free(ctx);
  } else {
    active_process_find(ctx);
  }

  discord_update_presence(ctx);
  sd_notify(0, "READY=1");

  return 0;
}

int on_process_event(sd_event_source *s, int nlfd, uint32_t revents, void *ud) {
  Context *ctx = ud;

  struct proc_event proc;
  bzero(&proc, sizeof(proc));
  int rc = prkit_monitor_read_event(nlfd, &proc);

  if (rc < 0) {
    log_errno(-rc, "prkit_monitor_read_event");
  } else {
    if (proc.what & PROC_EVENT_EXEC) {
      ConfigEntry *active = NULL;
      pid_t orig_pid = ctx->active.pid;
      if (orig_pid != -1) {
        active = find_matching_entry(ctx->config, ctx->active.path, ctx->active.name, NULL);
      }

      try_set_active_process_pid(ctx, proc.event_data.exec.process_pid, active);

      if (orig_pid != ctx->active.pid) {
        discord_update_presence(ctx);
      }
    }

    if (proc.what & PROC_EVENT_EXIT && proc.event_data.exit.process_pid == ctx->active.pid) {
      active_process_free(ctx);
      active_process_find(ctx);

      discord_update_presence(ctx);
    }
  }

  return 0;
}

int setup_signal_handlers(Context *ctx, sd_event *event) {
  sigset_t mask;
  sigemptyset(&mask);
  sigaddset(&mask, SIGINT);
  sigaddset(&mask, SIGTERM);
  sigaddset(&mask, SIGHUP);
  sigaddset(&mask, SIGUSR1);

  if (sigprocmask(SIG_BLOCK, &mask, NULL) == -1) {
    log_errno(errno, "sigprocmask(SIG_BLOCK, {...})");
    return -1;
  }

  int rc = 0;

  if ((rc = sd_event_add_signal(event, NULL, SIGINT, NULL, NULL)) < 0 ||
      (rc = sd_event_add_signal(event, NULL, SIGTERM, NULL, NULL))) {
    log_errno(-rc, "sd_event_add_signal({SIGINT, SIGTERM})");
    return -1;
  }

  rc = sd_event_add_signal(event, NULL, SIGHUP, on_config_reload_request, ctx);
  if (rc < 0) {
    log_errno(-rc, "sd_event_add_signal(SIGHUP)");
    return -1;
  }

  return 0;
}

sd_event *event_init(Context *ctx, int nlfd) {
  cleanup(sd_event_unrefp) sd_event *event = NULL;

  int rc = sd_event_default(&event);
  if (rc < 0) {
    log_errno(-rc, "sd_event_default");
    return NULL;
  }

  rc = sd_event_set_watchdog(event, 1);
  if (rc < 0) {
    log_errno(-rc, "sd_event_set_watchdog");
    return NULL;
  }

  rc = sd_event_add_io(event, NULL, nlfd, EPOLLIN, on_process_event, ctx);
  if (rc < 0) {
    log_errno(-rc, "sd_event_add_io(netlink)");
    return NULL;
  }

  if (setup_signal_handlers(ctx, event) == -1) {
    return NULL;
  }

  return stealp(&event);
}

int main() {
  cleanup(closep) int nlfd = -1;
  int rc = prkit_monitor_open(&nlfd);
  if (rc < 0) {
    log_errno(-rc, "prkit_monitor_open");
    return 3;
  }

  cleanup(context_free) Context ctx = {0};
  if (context_open(&ctx) == -1) {
    return 3;
  }

  cleanup(sd_event_unrefp) sd_event *event = event_init(&ctx, nlfd);
  if (event == NULL) {
    return 3;
  }

  if (config_load(&ctx) == -1) {
    config_free(&ctx);
  } else {
    active_process_find(&ctx);
  }

  discord_update_presence(&ctx);
  sd_notify(0, "READY=1");

  rc = sd_event_loop(event);
  sd_notify(0, "STOPPING=1");

  if (rc < 0) {
    log_errno(-rc, "sd_event_loop");
    return 3;
  }

  return 0;
}
