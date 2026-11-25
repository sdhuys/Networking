#!/usr/bin/env bash
# Interop tests: your stack against the Linux kernel's TCP over tap0.
#
#   sudo tests/interop/run_interop.sh build/interop_peer
#
# Each scenario starts interop_peer (which creates tap0 = 192.168.100.1, stack = .2),
# runs a Linux peer against it, and checks the data echoed back is identical.
# Impairments: netem on tap0 affects Linux -> stack; STACK_DROP_PCT affects stack -> Linux.
# Logs and packet captures (if tcpdump is installed) go to interop-logs/.
#
# Needs: root, python3, iproute2 (tc) with the netem module; tcpdump optional.

set -u
PEER=${1:-build/interop_peer}
HERE=$(cd "$(dirname "$0")" && pwd)
LINUX_PEER="python3 $HERE/linux_peer.py"
LOGS=${LOGS:-interop-logs}
CASE_TIMEOUT=${CASE_TIMEOUT:-120} # seconds per scenario before it counts as stalled
STACK_IP=192.168.100.2
TAP_IP=192.168.100.1
PASS=0
FAIL=0

if [[ $EUID -ne 0 ]]; then
	echo "run as root (creating tap0 and using tc need it)"; exit 2
fi
if [[ ! -x $PEER ]]; then
	echo "interop_peer not found at $PEER; build it with: cmake --build build --target interop_peer"; exit 2
fi
mkdir -p "$LOGS"
SKIP=0

# netem check: needs the sch_netem kernel module (modprobe sch_netem)
HAVE_NETEM=0
if ip link add itest0 type dummy 2>/dev/null; then
	tc qdisc add dev itest0 root netem delay 1ms 2>/dev/null && HAVE_NETEM=1
	ip link del itest0
fi
[[ $HAVE_NETEM -eq 0 ]] && echo "note: tc netem not available (try: modprobe sch_netem); scenarios that need it are skipped"

csum_errors() { awk '/^Tcp:/ {if (++n == 2) print $NF}' /proc/net/snmp; } # Tcp InCsumErrors

wait_for_tap() {
	for _ in $(seq 100); do
		ip link show tap0 >/dev/null 2>&1 && ip addr show tap0 | grep -q "$TAP_IP" && return 0
		sleep 0.05
	done
	return 1
}

# run_case <name> <netem args or ""> <stack drop %> <stack mode> <bytes> <conns>
run_case() {
	local name=$1 netem=$2 drop=$3 mode=$4 bytes=$5 conns=$6
	local log="$LOGS/$name"
	local before after rc peer_pid cap_pid=""
	before=$(csum_errors)
	echo "=== $name: $mode, ${bytes} bytes x $conns, netem='${netem:-none}', stack drop ${drop}%"
	if [[ -n $netem && $HAVE_NETEM -eq 0 ]]; then
		echo "  SKIP (needs netem)"; SKIP=$((SKIP+1)); return
	fi

	if [[ $mode == stack-server ]]; then
		STACK_DROP_PCT=$drop timeout "$CASE_TIMEOUT" "$PEER" echo-server 9000 "$conns" >"$log.stack.out" 2>"$log.stack.err" &
		peer_pid=$!
		wait_for_tap || { echo "  tap0 did not come up"; kill $peer_pid 2>/dev/null; FAIL=$((FAIL+1)); return; }
		[[ -n $netem ]] && tc qdisc add dev tap0 root netem $netem
		command -v tcpdump >/dev/null && { tcpdump -i tap0 -w "$log.pcap" -s 128 >/dev/null 2>&1 & cap_pid=$!; sleep 0.5; }
		for _ in $(seq 100); do grep -q READY "$log.stack.out" && break; sleep 0.05; done
		timeout "$CASE_TIMEOUT" $LINUX_PEER client $STACK_IP 9000 "$bytes" "$conns" | tee "$log.linux.out"
		rc=${PIPESTATUS[0]}
		wait $peer_pid; local prc=$?
		[[ $prc -eq 124 ]] && echo "  stalled: no result within ${CASE_TIMEOUT}s"
		[[ $prc -ne 0 ]] && rc=1
	else
		# Linux echo server on the TAP address; it can only bind once tap0 exists, so the
		# stack client creates tap0 first and waits 2 s before it connects.
		STACK_DROP_PCT=$drop timeout "$CASE_TIMEOUT" "$PEER" client $TAP_IP 9001 "$bytes" "$conns" >"$log.stack.out" 2>"$log.stack.err" &
		peer_pid=$!
		wait_for_tap || { echo "  tap0 did not come up"; kill $peer_pid 2>/dev/null; FAIL=$((FAIL+1)); return; }
		[[ -n $netem ]] && tc qdisc add dev tap0 root netem $netem
		command -v tcpdump >/dev/null && { tcpdump -i tap0 -w "$log.pcap" -s 128 >/dev/null 2>&1 & cap_pid=$!; }
		timeout "$CASE_TIMEOUT" $LINUX_PEER echo-server $TAP_IP 9001 "$conns" >"$log.linux.out" 2>&1 &
		local lin_pid=$!
		wait $peer_pid; rc=$?
		[[ $rc -eq 124 ]] && echo "  stalled: no result within ${CASE_TIMEOUT}s"
		wait $lin_pid || rc=1
		grep -aE "^CONN" "$log.stack.out"
	fi

	[[ -n $cap_pid ]] && kill $cap_pid 2>/dev/null
	after=$(csum_errors)
	if [[ $after -gt $before ]]; then
		echo "  Linux counted $((after - before)) TCP checksum error(s) on segments from the stack"
		rc=1
	fi
	if [[ $rc -eq 0 ]]; then echo "  PASS"; PASS=$((PASS+1)); else echo "  FAIL (logs: $log.*)"; FAIL=$((FAIL+1)); fi
	sleep 0.5 # let tap0 disappear before the next case
}

run_case clean_stack_server   ""                                0 stack-server 1048576 1
run_case clean_stack_client   ""                                0 stack-client 1048576 1
run_case big_stack_server     ""                                0 stack-server 20971520 1
run_case many_conns_server    ""                                0 stack-server 65536 20
run_case many_conns_client    ""                                0 stack-client 65536 20
run_case delay_stack_server   "delay 20ms 5ms"                  0 stack-server 4194304 1
run_case loss_to_stack        "loss 3%"                         0 stack-server 2097152 1
run_case loss_from_stack      ""                                3 stack-server 2097152 1
run_case loss_both_client     "loss 2%"                         2 stack-client 2097152 1
run_case reorder_to_stack     "delay 10ms reorder 25% 50%"      0 stack-server 2097152 1
run_case duplicate_to_stack   "duplicate 5%"                    0 stack-server 2097152 1
run_case everything           "delay 10ms 5ms loss 2% duplicate 2% reorder 10% 50%" 2 stack-server 2097152 1

echo
echo "interop: $PASS passed, $FAIL failed, $SKIP skipped (logs in $LOGS/)"
[[ $FAIL -eq 0 ]]
