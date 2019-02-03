#!/usr/bin/env sh

if which setcap >/dev/null 2>&1; then
  setcap cap_net_admin+ep "${DESTDIR}/${MESON_INSTALL_PREFIX}/bin/discord-linux-rpc" || \
    echo "Failed to setcap cap_net_admin on ${DESTDIR}/${MESON_INSTALL_PREFIX}/discord-linux-rpc"
fi
