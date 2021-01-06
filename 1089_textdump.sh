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

if [ -z "$LOG_DIR_1089" ]; then
	LOG_DIR_1089="c:/path/to/1089/log/dir/"
fi

SED_FLAGS=""
if [ "$(uname -o)" == "MS/Windows" ]; then
	true;
else
	SED_FLAGS="--unbuffered"
fi

set -x
python3 -u "$DIR"/tcpproxy.py -s5 -li 0.0.0.0 -lp "$PORT" -ac "$CA_PEM" -ak "$CA_KEY_PEM" -s -v -im "textdump:logdir=\"$LOG_DIR_1089\"" -om "textdump:logdir=\"$LOG_DIR_1089\""

#python3 -u "$DIR"/tcpproxy.py -s5 -lp "$PORT" -ac "$CA_PEM" -ak "$CA_KEY_PEM" -s -v -im "textdump" -om "textdump"
