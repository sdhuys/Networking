# Tests

Three levels, from fast and exact to slow and realistic:

| Suite | What it runs | Time | Finds |
|---|---|---|---|
| `unit_tests` | One stack, no threads, a fake clock. The test plays the remote peer: it builds every segment by hand and checks every segment the stack sends. | seconds | protocol behaviour, timers, option handling, packet leaks, deadlocks |
| `system_tests` | Two stacks on their real RX, TX and timer threads, joined by a simulated link that drops, duplicates, delays and reorders frames. | ~30 s | data corruption, stalls under loss, races (with ThreadSanitizer) |
| `interop` | The stack on `tap0` against the Linux kernel's TCP, with `tc netem` impairments. | a few minutes | interoperability with a real, independent TCP |

Nothing in `src/` was changed for the tests. They link two replacements instead:
`tests/fakes/fake_time.c` (a clock the unit tests move by hand) and
`tests/fakes/fake_random.c` (the 5% send-side drop in `send_tcp_down` becomes 0% unless a test or
`STACK_DROP_PCT` asks for it). The main `networking` binary still links the real `time_now.c` and `random.c`.

## Running

```sh
cmake -S . -B build
cmake --build build --target check        # builds both suites, runs every test via ctest

# or run a suite directly, optionally filtered
cmake --build build --target unit_tests system_tests
./build/unit_tests --gtest_filter='Data.*'
./build/system_tests --gtest_filter='Transfer.TwoPercentLoss'
```

The stack prints a lot. The test report goes to stderr; the stack's stdout goes to `/dev/null`,
or to a file with `STACK_LOG=stack.log ./build/unit_tests ...`.

### Sanitizers

Use a separate build directory per sanitizer:

```sh
cmake -S . -B build-asan -DSTACK_SANITIZE=address   # AddressSanitizer + UBSan
cmake --build build-asan --target unit_tests system_tests && ./build-asan/unit_tests

cmake -S . -B build-tsan -DSTACK_SANITIZE=thread    # ThreadSanitizer
cmake --build build-tsan --target system_tests && ./build-tsan/system_tests
```

The system tests run clean under ThreadSanitizer. UBSan reports one misaligned 16-bit load in
`calc_ipv4_checksum` (`checksum.c`): harmless on x86, but it would fault on strict-alignment CPUs.

### Interop with Linux

Needs root, `python3`, `iproute2` with the netem module; `tcpdump` is optional (captures go next to the logs).

```sh
cmake --build build --target interop_peer
sudo tests/interop/run_interop.sh build/interop_peer
```

`interop_peer` sets up `tap0` with the stack's own `tap_setup`, the same interfaces as `main.c`
and a default route via 192.168.100.1. `tap_setup` fails on a kernel booted without IPv6
(it can't write `disable_ipv6`).

Each scenario creates `tap0` (192.168.100.1, the stack is .2), runs an echo test and checks every
byte that comes back. In `stack-server` scenarios Linux is the client; in `stack-client` scenarios
the stack connects to a Linux echo server. `netem` impairs Linux → stack; `STACK_DROP_PCT` impairs
stack → Linux. Scenarios needing netem are skipped if the `sch_netem` module isn't available
(`sudo modprobe sch_netem`). A scenario that produces no result within `CASE_TIMEOUT` seconds
(default 120) counts as stalled.

Logs and `.pcap` files land in `interop-logs/`; `tcpdump -nn -r interop-logs/<case>.pcap` shows what
happened. The script also fails a scenario if Linux counted TCP checksum errors (`/proc/net/snmp`,
`InCsumErrors`) on segments from the stack.

## How the unit tests work

`tests/unit/stack_fixture.hpp` is the fixture every unit test uses:

- `listen()`, `open_passive()`, `open_active()` set up a connection and return a `PeerConn`:
  the peer's view of sequence numbers, window and negotiated options.
- `peer_send(c, flags, payload)` sends a segment from the peer; `inject(seg)` sends any hand-built one.
- `next_out()` runs the TX worker and returns the next segment the stack sent. Every segment is
  checked on the way out: IP and TCP checksums, option encoding, the 40-byte option limit, the
  data offset, the 1514-byte frame limit, and the IP length.
- `advance(ms)` moves the fake clock in 10 ms steps, running timers and the TX worker at each step.
- `app_read()` / `app_write()` call the socket API on another thread with a timeout.

Two checks run in every test without being asked:

- **Deadlock guard.** Every call into the stack runs on a helper thread. If it doesn't return within
  2 s, the test fails with "stack did not return within 2 s while processing <segment>". Attach a
  debugger to see the stuck threads.
- **Packet-leak check.** After each test, the packet pool must be back to where it started. A
  failure here means a `retain_pkt` without a matching `release_pkt`.

Frames are built and parsed by `tests/support/wire.cpp` (TCP) and `tests/unit/frames.hpp` (UDP,
ICMP, raw IPv4), which share no code with the stack, so a bug in the stack's checksum or option
code can't cancel itself out.

Loopback has no RX thread in the unit tests: `th_drain_ingress()` processes what loopback put on
the ingress queue. The data-structure tests reach `struct pkt` only through the opaque
`th_pkt_*` / `th_ring_*` functions, because `pkt.h` uses C11 atomics that C++ can't compile.

### Tests for open findings

`tests/unit/open_findings_test.cpp` has tests for review findings that are still open: 22, 23,
24, 25 (a to d), 27, 28, 32, 33 and 34. They're disabled by default because they're expected to
fail. Run them with:

```sh
./build/unit_tests --gtest_also_run_disabled_tests --gtest_filter='Open*'
```

Run `DISABLED_F22_InWindowSynGetsChallengeAck` on its own (`--gtest_filter=*F22*`): on current
main it aborts the process (a packet is released twice on the RST path it exercises).

When you fix a finding and its test passes, move the test into the suite it belongs to without
the `DISABLED_` prefix, so it guards against regressions. Findings 20, 21, 26 and 30 have been
moved this way (`window_test.cpp`, `network_test.cpp`).

## Layout

```
tests/
  fakes/       fake_time.c, fake_random.c, fake_env.h   link-time replacements
  support/     harness.c/.h   C glue: builds stacks without TAP, drives TX and timers
               wire.cpp/.hpp  independent frame builder and parser
               blocking.hpp   blocking calls with timeouts
               test_main.cpp  gtest main (report to stderr, stack output to STACK_LOG)
  unit/        handshake, data, close, cookie, robustness   TCP behaviour
               window       acceptability test, rate limit, zero window, window scaling, SND.WL1/WL2
               network      ARP retries and flushing, routing via a gateway, IPv4 options/length, UDP checksums
               l3           ICMP echo, Ethernet demux, IPv4 input checks, strong host, loopback,
                            UDP sockets (ports, demux, rebinding), ARP pending queue and spoofed replies
               structures   heap, queue, packet pool and ring, socket fds, checksums, routing table
               timer        the timer manager and timer_should_execute() on their own
               open_findings  disabled tests for review findings still open
  system/      link.hpp (simulated link), transfer_test.cpp
  interop/     interop_peer.c, linux_peer.py, run_interop.sh
```

Each test stack has two interfaces, like `main.c`: `test0` (the "wire", whose transmit function
hands frames to the test) and loopback. `th_stack_create_gw()` adds a default route via a
gateway on `test0`'s subnet.

The tests only use the stack through public headers and structs. If you rename a struct field the
harness reads (`harness.c`, `th_conn_lookup`), update it there.
