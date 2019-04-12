# discord-linux-rpc

Allows you to expose some of your running processes to Discord, even if it's the Flatpak version,
via rich presence.

## Features

- Updates your rich presence with the processes you want.
- Allows you to configure multiple processes that can be picked up.
- Automatically switches between processes as they are started and stopped.

## Installation

RPMs will come SOON(tm), for now you have to build from source.

## Installing from source

### Requirements

You need:

- A C compiler
- [Meson](https://mesonbuild.com/) and Ninja
- systemd and libsystemd
- libcap/setcap
- [yajl](https://lloyd.github.io/yajl/)

```bash
# Installing dependencies on Fedora
$ sudo dnf install gcc meson libcap systemd-devel yajl-devel
# Installing dependencies on Arch
$ sudo pacman -S base-devel libcap meson yajl
```

### Building and installing

Just run:

```
# configure
$ meson _build
# build and install (you shouldn't need root, Meson will use polkit if possible)
$ ninja -C _build install
```

Now, to enable the service to run on boot and start it:

```
$ systemctl --user enable --now discord-linux-rpc
```

## Usage

discord-linux-rpc reads its configuration from `~/.config/discord-linux-rpc/proc`. In order to
configure it, however, you need to create a Discord application for each process you want to
show up on your rich presence.

### Getting the client IDs

Head over to the [Discord developer portal](https://discordapp.com/developers/applications/)
and create a new application. Name it the name you want to appear you're playing when your
process is running. If you want it to have a picture, head over to the *Rich Presence* tab of
the application's settings and upload the image as a rich presence asset, giving it the name
`discord-linux-rpc`.

### Setting up the configuration file

**NOTE:** There should be a GUI for this SOON(tm).

```
# This file should be stored at: ~/.config/discord-linux-rpc/proc
# Lines beginning with a # are comments.
# The file contains data in the following format:
# [CLIENT-ID] [name|path] [MATCHER]
# or
# [CLIENT-ID] [name|path] [MATCHER] -- [STATE]

# If a process matches the given MATCHER (simply a plain string) via its name or path,
# then the rich presence will be set using CLIENT-ID, and the state will be STATE if it
# is given.

# - CLIENT-ID is the Discord client ID you want this process to use.
# - name|path determines whether the process will be matched via its name or
#   its path. If a process matches the given MATCHER by name or path, then
# - If name was given, then MATCHER is the name of the process to match.
    If path was given, then MATCHER is the full path to the process.
# STATE is optional, it will be the rich presence state associated with the process.

# None of the above probably made sense, so here are some examples:

# This will match a process named "sleep". When sleep is running, then the rich presence
# will be associated with the client ID 000000000000000000, meaning the name given to the
# application will appear as what you're playing.
000000000000000000 name sleep

# This instead matches the program /usr/lib/systemd/systemd by its path.
# In addition, the -- means that a state is being given. The state is "systemd power".
# Whenever discord-linux-rpc uses this process, it will set the rich presence state to
# "systemd power".
111111111111111111 path /usr/lib/systemd/systemd -- systemd power

# This is similar to the first one, but it shows that the process name can have spaces,
# and it shows that you can still pass a custom state string.
22222222222222222 name My Game -- some state goes here

# Note: ORDER MATTERS! In the above config, sleep is prioritized over systemd, and systemd
# is prioritized over My Game. This means that if sleep is running, discord-linux-rpc will
# show you're playing sleep's client ID. If sleep stops, then discord-linux-rpc will go
# down the list, see systemd, and use that. My Game will never be used, because systemd is
# always going to be running.
```

### Controlling the daemon

Whenever you change your config file, run:

```
$ systemctl --user reload discord-linux-rpc
```

## Future ideas

- System packages. (Maybe also build on a really old system so that it'll run anywhere systemd
  is available, and then distribute those binaries.)
- A GUI to edit the config file and reload the daemon.
- Later on: maybe a D-Bus API to be make it easy for other Linux apps to set Discord rich
  presence without having to worry about whether or not the Flatpak is being used?
