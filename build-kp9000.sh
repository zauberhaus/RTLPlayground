#!/bin/bash
# Build firmware images for the KP-9000-9XHML-X V2.2 and V3.1 boards.
# Images end up in output/<MACHINE>/rtlplayground-*.bin
set -e
cd "$(dirname "$0")"

MACHINES="KP_9000_9XHML_X_V3_1 KP_9000_9XHML_X_V2_2"

for m in $MACHINES; do
	echo "=== Building $m ==="
	make MACHINE="$m" "$@"
done

echo
echo "Built images:"
for m in $MACHINES; do
	ls -l output/"$m"/*.bin
done
