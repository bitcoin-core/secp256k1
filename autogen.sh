#!/bin/sh
set -e
command -v autoreconf >/dev/null || \
  (echo "configuration failed, please install autoconf first" >&2 && exit 1)
autoreconf --install --force --warnings=all
