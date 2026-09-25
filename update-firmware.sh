#!/usr/bin/env bash
#
# Pull the latest changes from main and build a firmware .bin file that can
# be uploaded through the RTLPlayground web interface ("Firmware update" tab).
#
# Usage:
#   ./update-firmware.sh [--oem] [--mac aa:bb:cc:dd:ee:ff] [MACHINE]
#
# --oem            Also build the OEM upgrade image (installer/output/rtlplayground_oem_upgrade.bin),
#                   needed only to move a device off its original OEM firmware onto RTLPlayground
#                   for the first time (README section 2). Not needed for devices already running
#                   RTLPlayground.
# --mac <address>  Bake a "mac <address>" line into the default config.txt for this build only,
#                   so the device comes up with that management MAC at first boot. config.txt is
#                   restored to its original content once the build finishes.
#
# MACHINE defaults to $MACHINE if set in the environment, otherwise falls
# back to the machine that was last built in output/.

set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")"

DOCKER_IMAGE=rtlplayground-dev

# --- parse args ----------------------------------------------------------------
BUILD_OEM=0
MAC_ADDRESS=""
while [ $# -gt 0 ]; do
	case "$1" in
	--oem)
		BUILD_OEM=1
		shift
		;;
	--mac)
		MAC_ADDRESS="${2:-}"
		if [ -z "$MAC_ADDRESS" ]; then
			echo "error: --mac requires an address, e.g. --mac aa:bb:cc:dd:ee:ff" >&2
			exit 1
		fi
		shift 2
		;;
	*)
		break
		;;
	esac
done
if [ -n "$MAC_ADDRESS" ] && ! [[ "$MAC_ADDRESS" =~ ^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$ ]]; then
	echo "error: invalid MAC address '$MAC_ADDRESS', expected format aa:bb:cc:dd:ee:ff" >&2
	exit 1
fi

# --- determine target machine -------------------------------------------------
MACHINE="${1:-${MACHINE:-}}"
if [ -z "$MACHINE" ] && [ -L output/rtlplayground.bin ]; then
	MACHINE="$(basename "$(dirname "$(readlink output/rtlplayground.bin)")")"
fi
if [ -z "$MACHINE" ]; then
	echo "error: no MACHINE given and none could be detected from output/." >&2
	echo "usage: $0 MACHINE   (e.g. $0 KP_9000_9XHML_X_V3_1)" >&2
	exit 1
fi
echo "==> Target machine: $MACHINE"

# --- refuse to pull over local changes ---------------------------------------
current_branch="$(git rev-parse --abbrev-ref HEAD)"
if [ "$current_branch" != "main" ]; then
	echo "error: currently on branch '$current_branch', not 'main'. Switch to main first." >&2
	exit 1
fi
if [ -n "$(git status --porcelain --untracked-files=no)" ]; then
	echo "error: working tree has uncommitted changes to tracked files. Commit or stash them first." >&2
	exit 1
fi

# --- pull latest main ---------------------------------------------------------
echo "==> Fetching latest main..."
git fetch origin main
git merge --ff-only origin/main

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

# --- build the dev container --------------------------------------------------
echo "==> Building dev container image..."
docker build -t "$DOCKER_IMAGE" .

# --- build the firmware --------------------------------------------------------
echo "==> Building firmware for MACHINE=$MACHINE..."
docker run --rm -v "$(pwd):/workspace" "$DOCKER_IMAGE" make MACHINE="$MACHINE"

BIN_PATH="$(readlink -f output/rtlplayground.bin)"
echo "==> Build complete."
echo "    Upload this file via the web interface's \"Firmware update\" tab:"
echo "    $BIN_PATH"

# --- optionally build the OEM upgrade image -----------------------------------
if [ "$BUILD_OEM" -eq 1 ]; then
	echo "==> Building OEM upgrade image..."
	docker run --rm -v "$(pwd):/workspace" -w /workspace/installer "$DOCKER_IMAGE" make
	OEM_BIN_PATH="$(readlink -f installer/output/rtlplayground_oem_upgrade.bin)"
	echo "==> OEM upgrade image built."
	echo "    Upload this file ONLY through the original OEM web interface (one-time move to RTLPlayground):"
	echo "    $OEM_BIN_PATH"
fi
