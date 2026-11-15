#!/usr/bin/env bash
#
# Build a firmware .bin file locally, using the locally installed
# toolchain (sdcc, make, python3, ... - see README for what to
# install), that can be uploaded through the RTLPlayground web
# interface ("Firmware update" tab).
#
# Usage:
#   ./update-firmware.sh [--machine MACHINE] [--oem] [--mac aa:bb:cc:dd:ee:ff]
#
# --machine <name>  Target machine, e.g. KP_9000_9XHML_X_V3_1 (see machine.h
#                    for the full list). Defaults to $MACHINE if set in the
#                    environment; if not given at all, falls back to
#                    whichever machine is currently active in machine.h.
# --oem             Also build the OEM upgrade image
#                    (installer/output/rtlplayground_oem_upgrade.bin), needed
#                    only to move a device off its original OEM firmware onto
#                    RTLPlayground for the first time (README section 2). Not
#                    needed for devices already running RTLPlayground.
# --mac <address>   Bake a "mac <address>" line into the default config.txt
#                    for this build only, so the device comes up with that
#                    management MAC at first boot. config.txt is restored to
#                    its original content once the build finishes.

set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")"

# --- parse args ----------------------------------------------------------------
BUILD_OEM=0
MAC_ADDRESS=""
TARGET_MACHINE="${MACHINE:-}"
while [ $# -gt 0 ]; do
	case "$1" in
	--oem)
		BUILD_OEM=1
		shift
		;;
	--machine)
		TARGET_MACHINE="${2:-}"
		if [ -z "$TARGET_MACHINE" ]; then
			echo "error: --machine requires a name, e.g. --machine KP_9000_9XHML_X_V3_1" >&2
			exit 1
		fi
		shift 2
		;;
	--mac)
		MAC_ADDRESS="${2:-}"
		if [ -z "$MAC_ADDRESS" ]; then
			echo "error: --mac requires an address, e.g. --mac aa:bb:cc:dd:ee:ff" >&2
			exit 1
		fi
		shift 2
		;;
	-h|--help)
		sed -n '2,22p' "$0" | sed 's/^# \{0,1\}//'
		exit 0
		;;
	*)
		echo "error: unknown argument '$1' (see --help)" >&2
		exit 1
		;;
	esac
done
if [ -n "$MAC_ADDRESS" ] && ! [[ "$MAC_ADDRESS" =~ ^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$ ]]; then
	echo "error: invalid MAC address '$MAC_ADDRESS', expected format aa:bb:cc:dd:ee:ff" >&2
	exit 1
fi

# --- check the local toolchain is present --------------------------------------
for tool in sdcc make python3 gcc; do
	command -v "$tool" >/dev/null 2>&1 || {
		echo "error: '$tool' not found on PATH; see README for local build dependencies" \
		     "(or Dockerfile for the exact package list)." >&2
		exit 1
	}
done

# --- determine target machine -------------------------------------------------
MAKE_ARGS=()
if [ -n "$TARGET_MACHINE" ]; then
	MAKE_ARGS+=("MACHINE=$TARGET_MACHINE")
	echo "==> Target machine: $TARGET_MACHINE"
else
	echo "==> No --machine given; building whichever machine is currently active in machine.h"
fi

# --- optionally bake a MAC address into config.txt for this build only -------
if [ -n "$MAC_ADDRESS" ]; then
	CONFIG_BACKUP="$(mktemp)"
	cp config.txt "$CONFIG_BACKUP"
	trap 'mv "$CONFIG_BACKUP" config.txt' EXIT
	if grep -qi '^mac ' config.txt; then
		sed -i.bak "s/^mac .*/mac $MAC_ADDRESS/" config.txt && rm -f config.txt.bak
	else
		printf '\nmac %s\n' "$MAC_ADDRESS" >>config.txt
	fi
	echo "==> Baked mac $MAC_ADDRESS into config.txt for this build (restored afterward)"
fi

# --- build the firmware --------------------------------------------------------
echo "==> Building firmware..."
make "${MAKE_ARGS[@]}"

BIN_PATH="$(readlink -f output/rtlplayground.bin)"
echo "==> Build complete."
echo "    Upload this file via the web interface's \"Firmware update\" tab:"
echo "    $BIN_PATH"

# --- optionally build the OEM upgrade image -----------------------------------
if [ "$BUILD_OEM" -eq 1 ]; then
	echo "==> Building OEM upgrade image..."
	(cd installer && make)
	OEM_BIN_PATH="$(readlink -f installer/output/rtlplayground_oem_upgrade.bin)"
	echo "==> OEM upgrade image built."
	echo "    Upload this file ONLY through the original OEM web interface (one-time move to RTLPlayground):"
	echo "    $OEM_BIN_PATH"
fi
