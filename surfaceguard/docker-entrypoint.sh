#!/bin/sh
set -e
# Hosting volumes are usually mounted owned by root; give the app user its data dir.
if [ "$(id -u)" = "0" ]; then
    mkdir -p "$DATA_DIR"
    chown -R appuser:appuser "$DATA_DIR"
    exec setpriv --reuid=10001 --regid=10001 --init-groups "$@"
fi
exec "$@"
