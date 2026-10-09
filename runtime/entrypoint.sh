#!/bin/sh
set -eu
umask 077
test "$(id -u)" = 0
test -n "${CODER_INIT_SCRIPT:-}"
test -n "${AGENTICSANDBOX_IMAGE_DIGEST:-}"
# The Docker provider used by the candidate has no pids_limit field. The
# template starts this process behind a host-side gate that updates the live
# container cgroup before allowing Coder or task processes to start.
mkdir -p /run/coder
if [ -n "${AGENTICSANDBOX_PIDS_GATE:-}" ]; then
    case "$AGENTICSANDBOX_PIDS_GATE" in
        /run/coder/*) ;;
        *) echo "invalid PID gate path" >&2; exit 1 ;;
    esac
    pid_limit_ready() {
        for cgroup_file in /sys/fs/cgroup/pids.max /sys/fs/cgroup/pids/pids.max; do
            if [ -r "$cgroup_file" ]; then
                cgroup_value=$(cat "$cgroup_file" 2>/dev/null || true)
                case "$cgroup_value" in
                    ''|*[!0-9]*) ;;
                    *)
                        if [ "$cgroup_value" -ge 1 ] && [ "$cgroup_value" -le 128 ]; then
                            return 0
                        fi
                        ;;
                esac
            fi
        done
        return 1
    }
    i=0
    while [ ! -f "$AGENTICSANDBOX_PIDS_GATE" ] && ! pid_limit_ready; do
        if [ "$i" -ge 300 ]; then
            echo "timed out waiting for PID cgroup gate" >&2
            exit 1
        fi
        i=$((i + 1))
        sleep 0.1
    done
    unset AGENTICSANDBOX_PIDS_GATE
fi
agenticsandbox runtime-limits
agenticsandbox runtime-manifest verify >/dev/null
agenticsandbox runtime-storage
mkdir -p /run/coder/home /run/coder/tmp
printf '%s\n' "$CODER_INIT_SCRIPT" > /run/coder/init.sh
chmod 0700 /run/coder/init.sh
unset CODER_INIT_SCRIPT
export HOME=/run/coder/home TMPDIR=/run/coder/tmp
exec /bin/sh /run/coder/init.sh
