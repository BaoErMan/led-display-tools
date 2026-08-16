#!/usr/bin/env bash
cd "$(dirname "$0")"
exec python3 led_ambient_gui.py "$@"
