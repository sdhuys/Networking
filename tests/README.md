# Tests

Three levels, from fast and exact to slow and realistic:

| Suite | What it runs | Time | Finds |
|---|---|---|---|
| `unit_tests` | One stack, no threads, a fake clock. The test plays the remote peer: it builds every frame by hand and checks every frame the stack sends. About 160 tests. | seconds | protocol behaviour, timers, option handling, packet leaks, deadlocks |
| `system_tests` | Two stacks on their real RX, TX and timer threads, joined by a simulated link that drops, duplicates, delays and reorders frames. 14 tests. | ~30 s | data corruption, stalls under loss, races (with ThreadSanitizer) |
| `interop` | The stack on `tap0` against the Linux kernel's TCP, optionally with `tc netem` impairments. 12 scenarios. | a few minutes | interoperability with a real, independent TCP |

Nothing in `src/` was changed for the tests. They link two replacements instead:
`tests/fakes/fake_time.c` (a clock the unit tests move by hand) and
`tests/fakes/fake_random.c` (the 5% send-side drop in `send_tcp_down` becomes 0% unless a test or
`STACK_DROP_PCT` asks for it). The main `networking` binary still links the real `time_now.c` and
`random.c`.

## Building and running

Run everything from the repository's top-level folder.

```sh
cmake -S . -B build                      # configure, once (the first run downloads googletest)
cmake --build build --target check       # build both suites, then run every test through ctest
```

`cmake --build build` on its own only builds the default target, the `networking` executable: the
test executables are excluded from it, so build them by name (`--target unit_tests`, `--target
system_tests`) or through `check`.

`check` runs each test in its own process, so a crash or hang in one test can't take the others
with it. When any test fails, `ctest` exits with an error and the build ends with `gmake ... Error`
lines: look above them for the `The following tests FAILED:` list. To see why:

```sh
cd build && ctest --rerun-failed --output-on-failure
```

### Running a suite directly

Faster while you work on something, and you get the full gtest report:

```sh
cmake --build build --target unit_tests system_tests
./build/unit_tests
./build/system_tests

./build/unit_tests --gtest_filter='Window.*'            # one suite
./build/unit_tests --gtest_filter='Data.*Retransmit*'   # wildcards
./build/unit_tests --gtest_list_tests                   # every test name
```

The stack prints a lot. The test report goes to stderr; the stack's stdout goes to `/dev/null`,
or to a file with `STACK_LOG=stack.log ./build/unit_tests ...`. 

### Sanitizers

Use a separate build directory per sanitizer:

```sh
cmake -S . -B build-asan -DSTACK_SANITIZE=address   # AddressSanitizer + UBSan
cmake --build build-asan --target unit_tests system_tests
./build-asan/unit_tests && ./build-asan/system_tests

cmake -S . -B build-tsan -DSTACK_SANITIZE=thread    # ThreadSanitizer
cmake --build build-tsan --target system_tests
./build-tsan/system_tests
```

Both run clean apart from one UBSan report: a misaligned 16-bit load in `calc_ipv4_checksum`
(`checksum.c`). It is harmless on x86 but would fault on CPUs that require aligned loads.

### Interop with Linux

Needs root and `python3`. The scenarios with delay, loss, reordering or duplication also need
`iproute2` with the netem module (`sudo modprobe sch_netem`); without it they're skipped.
`tcpdump` is optional (captures go next to the logs).

```sh
cmake --build build --target interop_peer
sudo tests/interop/run_interop.sh build/interop_peer
```

`interop_peer` sets up `tap0` with the stack's own `tap_setup`, the same interfaces as `main.c`
(tap0 + loopback) and a default route via 192.168.100.1. `tap_setup` fails on a kernel booted
without IPv6, because it can't write `disable_ipv6`.

Each scenario creates `tap0` (192.168.100.1, the stack is .2), runs an echo test and checks every
byte that comes back. In `stack-server` scenarios Linux is the client; in `stack-client` scenarios
the stack connects to a Linux echo server. `netem` impairs Linux → stack; `STACK_DROP_PCT` impairs
stack → Linux. A scenario that produces no result within `CASE_TIMEOUT` seconds (default 120)
counts as stalled. `interop_peer` waits for its connections to finish closing before it exits,
so data still in the send buffer isn't lost when the process ends.

Logs and `.pcap` files land in `interop-logs/`; `tcpdump -nn -r interop-logs/<case>.pcap` shows
what happened. The script also fails a scenario if Linux counted TCP checksum errors
(`/proc/net/snmp`, `InCsumErrors`) on segments from the stack.

`loss_from_stack` (the stack drops 3% of what it sends) is a useful benchmark: it passes, but at
about 0.1 MB/s against 11 MB/s on a clean link, because every loss waits for a 1 s RTO
(findings 24 and 25).

## Disabled tests: open review findings

`tests/unit/open_findings_test.cpp` holds tests for review findings that are still open: 22, 23,
24, 25 (a to d), 27 (two tests), 28, 32, 33 and 34. Each describes the RFC behaviour and fails on
current main for the reason the finding gives, so they're disabled (`DISABLED_` prefix).

Run them once, without changing code, on the binary directly (`ctest` and `check` only list them
as "Not Run (Disabled)"):

```sh
./build/unit_tests --gtest_also_run_disabled_tests --gtest_filter='Open*'
./build/unit_tests --gtest_also_run_disabled_tests --gtest_filter='*F25a*'   # one finding
```

Run `DISABLED_F22_InWindowSynGetsChallengeAck` on its own (`--gtest_filter='*F22*'`): on current
main it aborts the whole process. The `RST_UNEXPECTED_SYN` branch in `process_tcp_segment` hands
the packet to `out_d->pkt_snd_now` without `retain_pkt`, so it is released twice and
`release_pkt`'s assert fires.

When you fix a finding and its test passes, enable it for good: remove the `DISABLED_` prefix and
move the test into the suite it belongs to, so it guards against regressions. Findings 20, 21, 26
and 30 have been moved this way, into `window_test.cpp` and `network_test.cpp`.

## How the unit tests work

`tests/unit/stack_fixture.hpp` is the fixture most unit tests use:

- `listen()`, `open_passive()`, `open_active()` set up a connection and return a `PeerConn`:
  the peer's view of sequence numbers, window and negotiated options.
- `peer_send(c, flags, payload)` sends a segment from the peer; `inject(seg)` sends any hand-built
  one.
- `next_out()` runs the TX worker and returns the next TCP segment the stack sent. Every segment is
  checked on the way out: IP and TCP checksums, option encoding, the 40-byte option limit, the
  data offset, the 1514-byte frame limit, and the IP length. `take_raw_frames()` returns every
  frame unparsed (ARP, UDP, ICMP).
- `advance(ms)` moves the fake clock in 10 ms steps, running timers and the TX worker at each step.
- `app_read()` / `app_write()` call the socket API on another thread with a timeout.

Two checks run in every test without being asked:

- **Deadlock guard.** Every call into the stack runs on a helper thread. If it doesn't return
  within 2 s, the test fails with "stack did not return within 2 s while processing <segment>".
  Attach a debugger to see the stuck threads.
- **Packet-leak check.** After each test, the packet pool must be back to where it started. A
  failure here means a `retain_pkt` without a matching `release_pkt`.

Each test stack has two interfaces, like `main.c`: `test0` (the "wire", whose transmit function
hands frames to the test) and loopback. Injected frames are marked as arriving on `test0`.
`th_stack_create_gw()` adds a default route via a gateway on `test0`'s subnet. Loopback has no RX
thread in the unit tests: `th_drain_ingress()` processes what loopback put on the ingress queue.

Frames are built and parsed by `tests/support/wire.cpp` (TCP) and `tests/unit/frames.hpp` (UDP,
ICMP, raw IPv4), which share no code with the stack, so a bug in the stack's checksum or option
code can't cancel itself out.

The tests never include stack headers that use C11 atomics (`pkt.h`, `arp.h`,
`tcp_conn_socket.h`, `tcp_listener_socket.h`): C++ can't compile them. Everything they need goes
through `harness.h`, including opaque `th_pkt_*` / `th_ring_*` functions for packets. The
data-structure tests include the plain headers (`heap.h`, `queue.h`, `routing_table.h`, ...)
directly.

## Layout

```
tests/
  fakes/       fake_time.c, fake_random.c, fake_env.h   link-time replacements
  support/     harness.c/.h   C glue: builds stacks without TAP, drives TX, timers and loopback
               wire.cpp/.hpp  independent TCP frame builder and parser
               blocking.hpp   blocking calls with timeouts
               test_main.cpp  gtest main (report to stderr, stack output to STACK_LOG)
  unit/        stack_fixture.hpp   the fixture
               frames.hpp          UDP / ICMP / raw IPv4 frame helpers
               handshake, data, close, cookie, robustness   TCP behaviour
               window         acceptability test, rate limit, zero window, window scaling,
                              SND.WL1/WL2
               network        ARP retries and flushing, routing via a gateway, IPv4 options and
                              length, UDP checksums
               l3             ICMP echo, Ethernet demux, IPv4 input checks, strong host, loopback,
                              UDP sockets, ARP pending queue and unsolicited replies
               structures     heap, queue, packet pool and ring, socket fds, checksums, routing
                              table
               timer          the timer manager and timer_should_execute() on their own
               open_findings  disabled tests for review findings still open
  system/      link.hpp (simulated link), transfer_test.cpp
  interop/     interop_peer.c, linux_peer.py, run_interop.sh
```

The tests only use the stack through public headers and structs. If you rename a struct field or
change a function the harness uses (`harness.c`: `construct_stack`, `set_nw_if_struct`,
`insert_incomplete_for_ip`, the fields read in `th_conn_lookup`), update it there.
