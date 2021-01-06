#!/bin/sh
set -eo pipefail

DIR=$( cd "$(dirname "$0")"; pwd -P )

if [ -f "$DIR"/env.source ]; then
	source "$DIR"/env.source
fi

PORT="$3"
if [ -z "$PORT" ]; then
	PORT=1089
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
		if [ ! -z "$MAIN_PID" ]; then
				kill $MAIN_PID || true
		fi
		rm "$DIR"/main.pid
}


LAST_PID=$(cat "$DIR"/main.pid) || true
if [ ! -z "$LAST_PID" ]; then
	kill $LAST_PID || true
fi

if [ "$1" == "x" ] ; then
	python3 -u "$DIR"/tcpproxy.py -s5 -lp "$PORT" -ac "$CA_PEM" -ak "$CA_KEY_PEM" -s -v
else
	python3 -u "$DIR"/tcpproxy.py -s5 -lp "$PORT" -ac "$CA_PEM" -ak "$CA_KEY_PEM" -s -v > $LOG_DIR"main_$(date +%Y%m%d_%H%M%S).log" 2>&1 &
fi

MAIN_PID=$!
echo PID: $MAIN_PID
echo $MAIN_PID > "$DIR"/main.pid
trap on_exit ABRT || true
trap on_exit QUIT || true
trap on_exit INT || true
trap on_exit HUP || true

while true; do
	sleep 0.5
	kill -0 $MAIN_PID > /dev/null 2>&1 || break
done

# rm "$DIR"/main.pid || true