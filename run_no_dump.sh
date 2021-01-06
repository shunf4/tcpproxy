#!/bin/sh
set -eo pipefail

DIR=$( cd "$(dirname "$0")"; pwd -P )

if [ -f "$DIR"/env.source ]; then
	source "$DIR"/env.source
fi

PORT="$1"
if [ -z "$PORT" ]; then
	PORT=1091
fi

if [ -z "$CA_PEM" ]; then
	CA_PEM="c:/path/to/ca.pem"
fi

if [ -z "$CA_KEY_PEM" ]; then
	CA_KEY_PEM="c:/path/to/ca_key.pem"
fi

if [ -z "$LOG_DIR" ]; then
	LOG_DIR="c:/path/to/log/dir/"
fi

function on_exit() {
	echo "** Trapped Exit Signal"
	if [ ! -z "$MAIN_PPID" ]; then
		kill $MAIN_PPID || true
		taskkill /f /pid `pgrep -P $MAIN_PPID` || true
	fi
	rm "$DIR"/main.ppid
}

LAST_PPID=$(cat "$DIR"/main.ppid) || true
if [ ! -z "$LAST_PPID" ]; then
	kill $LAST_PPID || true
	taskkill /f /pid `pgrep -P $LAST_PPID` || true
fi

if [ "$1" == "x" ] ; then
	python3 -u "$DIR"/tcpproxy.py -s5 -lp "$PORT" -ac "$CA_PEM" -ak "$CA_KEY_PEM" -s -v
else
	python3 -u "$DIR"/tcpproxy.py -s5 -lp "$PORT" -ac "$CA_PEM" -ak "$CA_KEY_PEM" -s -v > $LOG_DIR"main_$(date +%Y%m%d_%H%M%S).log" 2>&1 &
fi

MAIN_PPID=$!
echo PPID: $MAIN_PPID
echo $MAIN_PPID > "$DIR"/main.ppid
trap on_exit ABRT || true
trap on_exit QUIT || true
trap on_exit INT || true
trap on_exit HUP || true

while true; do
	sleep 0.5
	kill -0 $MAIN_PPID > /dev/null 2>&1 || break
done

# rm "$DIR"/main.pid || true
