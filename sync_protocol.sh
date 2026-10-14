#!/bin/bash
#
# sync_protocol.sh - Member 2
#
# The submission rules say every one of the four case folders must build on its
# own with "make clean && make". That means the protocol layer has to physically
# exist in all four. To avoid four diverging copies, there is exactly ONE master
# copy in _protocol_master/ and this script pushes it everywhere.
#
# RULE FOR THE WHOLE TEAM:
#   edit _protocol_master/protocol.cpp  ->  run ./sync_protocol.sh
#   never edit Part1/protocol.cpp (or any other copy) directly - it gets
#   overwritten the next time anyone runs this script.
#
# Usage:  ./sync_protocol.sh
#

set -e

MASTER="_protocol_master"
TARGETS="Part1 Part2_Case1 Part2_Case2 Part2_Case2_Enhanced"
SHARED="common_types.h protocol.h protocol.cpp"

cd "$(dirname "$0")"

if [ ! -d "$MASTER" ]; then
    echo "ERROR: $MASTER/ not found. Run this script from the project root."
    exit 1
fi

for f in $SHARED; do
    if [ ! -f "$MASTER/$f" ]; then
        echo "ERROR: $MASTER/$f is missing."
        exit 1
    fi
done

echo "Syncing protocol layer from $MASTER/ ..."
for dir in $TARGETS; do
    mkdir -p "$dir"
    for f in $SHARED; do
        cp "$MASTER/$f" "$dir/$f"
    done
    echo "  -> $dir/  (common_types.h, protocol.h, protocol.cpp)"
done

echo ""
echo "Done. Verifying that each copy still compiles cleanly..."
FAILED=0
for dir in $TARGETS; do
    if g++ -O2 -Wall -Wextra -pthread -std=c++17 -c "$dir/protocol.cpp" \
           -o /tmp/protocol_check_$$.o 2> /tmp/protocol_warn_$$.txt; then
        if [ -s /tmp/protocol_warn_$$.txt ]; then
            echo "  [WARN] $dir/protocol.cpp compiled but produced warnings:"
            cat /tmp/protocol_warn_$$.txt
            FAILED=1
        else
            echo "  [ OK ] $dir/protocol.cpp - zero warnings"
        fi
    else
        echo "  [FAIL] $dir/protocol.cpp did not compile:"
        cat /tmp/protocol_warn_$$.txt
        FAILED=1
    fi
done
rm -f /tmp/protocol_check_$$.o /tmp/protocol_warn_$$.txt

echo ""
if [ "$FAILED" -eq 0 ]; then
    echo "All four copies are in sync and warning-free."
else
    echo "Something is wrong - fix $MASTER/protocol.cpp and run this again."
    exit 1
fi
