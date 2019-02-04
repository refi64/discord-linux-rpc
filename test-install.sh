#!/usr/bin/bash

set -ex

install -Dm 755 _build/discord-linux-rpc /usr/bin/discord-linux-rpc
install -Dm 644 _build/discord-linux-rpc.service /usr/lib/systemd/user/discord-linux-rpc.service
DESTDIR= MESON_INSTALL_PREFIX=/usr . misc/setcap-net-admin.sh
