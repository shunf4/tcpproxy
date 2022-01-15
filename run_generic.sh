#!/bin/sh
set -eo pipefail

DIR=$( cd "$(dirname "$0")"; pwd -P )
cd "$DIR"

if [ -f "$DIR"/env.source ]; then
	source "$DIR"/env.source
fi

FLAG_ENABLE_TEXT_DUMP=''
FLAG_ENABLE_HEX_DUMP=''
FLAG_SHOULD_DECRYPT_TLS=''
FLAG_SHOULD_OUTPUT_TO_FILE=''

while true; do
	case "$1" in
		--text-dump ) FLAG_ENABLE_TEXT_DUMP=1; shift ;;
		--hex-dump ) FLAG_ENABLE_HEX_DUMP=1; shift ;;
		--decrypt-tls ) FLAG_SHOULD_DECRYPT_TLS='-s'; shift ;;
		--output-to-file ) FLAG_SHOULD_OUTPUT_TO_FILE=1; shift ;;
		--port ) PORT="$2"; shift; shift ;;
		--python-bin ) PYTHON_BIN="$2"; shift; shift ;;
		-- ) shift; break ;;
		* ) break ;;
	esac
done
		
if ! ( [ "$PORT" -gt 0 ] 2>/dev/null && [ "$PORT" -lt 65536 ] 2>/dev/null ) ; then
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
else
	mkdir -p "$LOG_DIR"
fi

if [ -z "$PYTHON_BIN" ]; then
	PYTHON_BIN="python3"
fi

if [ -z "$FLAG_SHOULD_OUTPUT_TO_FILE" ]; then
	"$PYTHON_BIN" -u "$DIR"/tcpproxy.py -s5 -lp "$PORT" -ac "$CA_PEM" -ak "$CA_KEY_PEM" ${FLAG_SHOULD_DECRYPT_TLS:+"$FLAG_SHOULD_DECRYPT_TLS"} -v ${FLAG_ENABLE_TEXT_DUMP:+"-im" "textdump:logdir=\"$LOG_DIR\"" "-om" "textdump:logdir=\"$LOG_DIR\""} ${FLAG_ENABLE_HEX_DUMP:+"-im" "hexdump:wsdirection=1:logdir=\"$LOG_DIR\"" "-om" "hexdump:wsdirection=1:logdir=\"$LOG_DIR\""} $@
else
	"$PYTHON_BIN" -u "$DIR"/tcpproxy.py -s5 -lp "$PORT" -ac "$CA_PEM" -ak "$CA_KEY_PEM" ${FLAG_SHOULD_DECRYPT_TLS:+"$FLAG_SHOULD_DECRYPT_TLS"} -v ${FLAG_ENABLE_TEXT_DUMP:+"-im" "textdump:logdir=\"$LOG_DIR\"" "-om" "textdump:logdir=\"$LOG_DIR\""} ${FLAG_ENABLE_HEX_DUMP:+"-im" "hexdump:wsdirection=1:logdir=\"$LOG_DIR\"" "-om" "hexdump:wsdirection=1:logdir=\"$LOG_DIR\""} $@ > $LOG_DIR"main_$(date +%Y%m%d_%H%M%S).log" 2>&1
fi
