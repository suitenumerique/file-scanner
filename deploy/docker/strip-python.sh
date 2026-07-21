#!/bin/sh
# Trim the uv-managed runtime for the distroless production image: remove tooling
# the app never uses at runtime — pip, idle, pydoc, C headers, pkg-config,
# tkinter/tcl, tests — plus the uv/uvx build binaries themselves. We build and
# manage everything with uv, so none of this is needed to *run*.
#
# Adapted from suitenumerique/messages (deploy/python-uv/strip-python.sh).
# Version-agnostic: the interpreter path comes from `uv python find`; stdlib
# paths glob python3.*. uv/uvx are removed LAST, after uv is used above.
set -eu

PYDIR=$(dirname "$(dirname "$(uv python find)")")

# shellcheck disable=SC2086  # deliberate globbing of the paths below
rm -rf \
    "$PYDIR"/bin/idle* "$PYDIR"/bin/pip* "$PYDIR"/bin/pydoc* "$PYDIR"/bin/*-config \
    "$PYDIR"/include "$PYDIR"/share \
    "$PYDIR"/lib/pkgconfig "$PYDIR"/lib/itcl* "$PYDIR"/lib/libtcl* \
    "$PYDIR"/lib/tcl* "$PYDIR"/lib/tk* "$PYDIR"/lib/thread* \
    "$PYDIR"/lib/python3.*/idlelib \
    "$PYDIR"/lib/python3.*/ensurepip \
    "$PYDIR"/lib/python3.*/tkinter \
    "$PYDIR"/lib/python3.*/turtledemo \
    "$PYDIR"/lib/python3.*/lib-dynload/_tkinter* \
    "$PYDIR"/lib/python3.*/lib-dynload/_ctypes_test* \
    "$PYDIR"/lib/python3.*/site-packages/pip "$PYDIR"/lib/python3.*/site-packages/pip-*.dist-info \
    "${UV_PYTHON_INSTALL_DIR:-/opt/python}"/.gitignore \
    "${UV_PYTHON_INSTALL_DIR:-/opt/python}"/.lock \
    "${UV_PYTHON_INSTALL_DIR:-/opt/python}"/.temp

# uv/uvx are build tools — never needed to run the app.
rm -f /bin/uv /bin/uvx
