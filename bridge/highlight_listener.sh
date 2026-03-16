#!/usr/bin/env sh
set -eu

HOST="${HIGHLIGHT_BRIDGE_HOST:-127.0.0.1}"
PORT="${HIGHLIGHT_BRIDGE_PORT:-31337}"
SAVE_CMD="${GSR_SAVE_CMD:-pkill -SIGUSR1 -f gpu-screen-recorder}"
LOG_FILE="${HIGHLIGHT_LOG_FILE:-/tmp/highlight_bridge.log}"
SAVE_ON_ASYNC="${HIGHLIGHT_SAVE_ON_ASYNC:-1}"
ASYNC_DELAY_SEC="${HIGHLIGHT_ASYNC_DELAY_SEC:-10}"

pending_pid=""

timestamp() {
    date '+%Y-%m-%d %H:%M:%S'
}

log() {
    line="$(timestamp) [highlight-listener] $*"
    printf '%s\n' "$line"
    printf '%s\n' "$line" >> "$LOG_FILE" || true
}

cleanup() {
    if [ -n "$pending_pid" ] && kill -0 "$pending_pid" 2>/dev/null; then
        kill "$pending_pid" 2>/dev/null || true
        wait "$pending_pid" 2>/dev/null || true
    fi
}

trap cleanup INT TERM EXIT

run_save() {
    # Some save commands may return non-zero even if the save succeeded.
    set +e
    out="$(sh -c "$SAVE_CMD" 2>&1)"
    code=$?
    set -e

    out_one="$(printf '%s' "$out" | tr '\n' ' ' | tr '\r' ' ')"
    if [ "$code" -eq 0 ]; then
        log "Replay save command exit=0"
    else
        log "Replay save command exit=$code (check output)"
    fi
    if [ -n "$out_one" ]; then
        log "Replay save output: $out_one"
    fi
}

schedule_delayed_save() {
    # Debounce: reset timer on every async event.
    if [ -n "$pending_pid" ] && kill -0 "$pending_pid" 2>/dev/null; then
        kill "$pending_pid" 2>/dev/null || true
        wait "$pending_pid" 2>/dev/null || true
        pending_pid=""
    fi

    if [ "$ASYNC_DELAY_SEC" = "0" ]; then
        run_save
        return
    fi

    (
        sleep "$ASYNC_DELAY_SEC"
        log "Delayed save fired after ${ASYNC_DELAY_SEC}s"
        run_save
    ) &
    pending_pid=$!
    log "Delayed save scheduled in ${ASYNC_DELAY_SEC}s pid=${pending_pid}"
}

log "Listening on ${HOST}:${PORT}"
log "Save command: ${SAVE_CMD}"
log "Log file: ${LOG_FILE}"
log "Save on async: ${SAVE_ON_ASYNC}"
log "Async delay sec: ${ASYNC_DELAY_SEC}"

if command -v socat >/dev/null 2>&1; then
    while true; do
        fifo="/tmp/highlight-bridge.${PORT}.$$"
        rm -f "$fifo" || true
        mkfifo "$fifo"

        # Run socat in the background and read events in the main shell (no pipeline subshell).
        socat -u "UDP-RECV:${PORT},bind=${HOST},reuseaddr" - 2>/dev/null >"$fifo" &
        socat_pid=$!

        while IFS= read -r event; do
            [ -n "$event" ] || continue
            log "Event: $event"
            case "$event" in
                video_highlight|screenshot_highlight|save_highlights)
                    run_save
                    ;;
                video_highlight_async)
                    if [ "$SAVE_ON_ASYNC" = "1" ]; then
                        schedule_delayed_save
                    fi
                    ;;
                *)
                    ;;
            esac
        done <"$fifo" || true

        kill "$socat_pid" 2>/dev/null || true
        wait "$socat_pid" 2>/dev/null || true
        rm -f "$fifo" || true

        log "socat exited; restarting in 1s"
        sleep 1
    done
elif command -v nc >/dev/null 2>&1; then
    while true; do
        event="$(nc -u -l -s "$HOST" -p "$PORT" -w 1 2>/dev/null || true)"
        [ -n "$event" ] || continue
        log "Event: $event"
        case "$event" in
            video_highlight|screenshot_highlight|save_highlights)
                run_save
                ;;
            video_highlight_async)
                if [ "$SAVE_ON_ASYNC" = "1" ]; then
                    schedule_delayed_save
                fi
                ;;
            *)
                ;;
        esac
    done
else
    log "Missing dependency: install socat or netcat (nc)."
    exit 1
fi
