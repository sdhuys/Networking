# Network Stack Implementation Summary

## Project Overview
A layered network protocol stack simulator written in C that interfaces with Linux TAP devices. It implements multiple protocol layers (Ethernet, ARP, IPv4, ICMP, TCP, UDP) in a modular, interconnected architecture.

**Location:** src

---

## Architecture

### Layered Design
Each layer is a `struct nw_layer` with:
- `send_down()` - Transmit to lower layer
- `rcv_up()` - Receive from lower layer
- `ups[]` / `downs[]` - Pointers to adjacent layers
- `context` - Layer-specific data

### Protocol Stack (Top to Bottom)
```
┌─────────────────────────────────┐
│  ICMP / TCP / UDP               │  Transport/Application
├─────────────────────────────────┤
│  IPv4                           │  Network
├─────────────────────────────────┤
│  ARP                            │  Link (Address Resolution)
├─────────────────────────────────┤
│  Ethernet                       │  Link (Frame)
├─────────────────────────────────┤
│  TAP Interface                  │  Physical (I/O)
└─────────────────────────────────┘
```

---

## File Breakdown

### **types.h**
Core type definitions and constants:
- `struct pkt` - Packet container (data buffer, length, offset, metadata)
- `struct pkt_metadata` - Source/destination MAC and IP addresses
- `struct nw_layer` - Generic network layer interface
- Protocol headers: `ethernet_header`, `arp_header`, `ipv4_header` (packed)
- Constants: `MAC_ADDR_LEN`, `IPV4_ADDR_LEN`, `MAX_ETH_FRAME_SIZE (1518)`
- Type aliases: `mac_address`, `ipv4_address`, `protocol_type`

### **tap.c / tap.h** - TAP Interface Layer
**Purpose:** Hardware I/O interface to Linux TUN/TAP device

**Functions:**
- `start_listening(fd, nw_layer)` - Main loop reading frames from TAP
- `send_up_to_ethernet(tap, data)` - Route packets upward
- `write_to_tap(tap, data)` - Write processed packets back to device

**Data Flow:** Reads raw frames → allocates `struct pkt` → passes to Ethernet layer

**⚠️ Issues:**
- Memory leak: `free(buffer)` called after `rcv_up()` despite buffer being referenced
- Should transfer ownership to callee, not free locally

### **ethernet.c / ethernet.h** - Ethernet Layer
**Purpose:** Frame-level MAC addressing and forwarding

**Functions:**
- `receive_frame_up(self, packet)` - Process incoming frames
  - Validates destination MAC (unicast to self or broadcast)
  - Extracts EtherType, routes to ARP (0x0806) or IPv4 (0x0800)
- `send_frame_down(self, packet)` - Add Ethernet header
  - Prepends MAC addresses
  - Updates packet offset
- `relevant_destination_mac(self, dest_mac)` - MAC filtering

**Data Structure:**
```c
struct ethernet_header {
    mac_address dest_mac;
    mac_address src_mac;
    protocol_type ethertype;
} __attribute__((packed));
```

### **arp.c / arp.h** - Address Resolution Protocol
**Purpose:** IP-to-MAC address mapping

**Functions:**
- `receive_arp_up(self, packet)` - Handle ARP requests/replies
  - Only supports Ethernet (hw_type=1) + IPv4
  - Ignores requests not targeting this host
  - Generates ARP replies
- `create_arp_response(self, packet, header, mac)` - Build reply
  - **Issue:** Modifies header in-place (swaps sender/target MAC and IP)
  - Returns same packet instead of new allocation
- `print_arp_header()` - Debug output

**Data Structure:**
```c
struct arp_header {
    uint16_t hw_type, proto_type, operation;
    unsigned char hw_addr_len, proto_addr_len;
    mac_address sender_mac, target_mac;
    ipv4_address sender_ip, target_ip;
} __attribute__((packed));
```

**Context:**
```c
struct arp_context {
    ipv4_address ipv4_address;
    mac_address mac_address;
    struct arp_table *arp_table_head;  // Linked list
};
```

### **ipv4.c / ipv4.h** - IPv4 Layer
**Purpose:** IP routing and forwarding

**Functions:**
- `receive_ipv4_up(self, packet)` - Route by protocol
  - Validates IP header checksum
  - Routes to ICMP (1), UDP (17), or TCP (6)
  - **Status:** Mostly stub implementation
- `send_ipv4_down(self, packet)` - Add IPv4 header

### **icmp.c / icmp.h** - ICMP Layer
**Purpose:** Echo requests/replies (ping)

**Functions:**
- `receive_icmp_up(self, packet)` - Handle incoming ICMP
- `send_icmp_down(self, packet)` - Send ICMP packets
- **Status:** Stub implementations (return 0)

### **udp.c / udp.h** - UDP Layer
**Purpose:** Connectionless transport

**Functions:**
- `receive_udp_up(self, packet)` - Receive UDP datagrams
- `send_udp_down(self, packet)` - Send UDP datagrams
- **Status:** Stub implementations

### **tcp.c / tcp.h** - TCP Layer
**Purpose:** Connection-oriented transport

**Functions:**
- `receive_tcp_up(self, packet)` - Handle TCP segments
- `send_tcp_down(self, packet)` - Send TCP segments
- **Status:** Stub implementations

### **stack_constructor.c / stack_constructor.h**
**Purpose:** Initialize and wire all layers together

**Functions:**
- `construct_stack(fd)` - Main initialization function
  - Creates instances of all 7 layers
  - Sets up `ups[]` and `downs[]` pointers
  - Assigns default MAC: `02:00:00:00:00:01`
  - Assigns default IPv4: `192.168.100.2`
  - Returns root layer (TAP)

### **main.c** - Entry Point
**Purpose:** Setup TAP device and start stack

**Functions:**
- `main()` - Calls `tap_setup()` and `construct_stack()`
- `tap_setup()` - Create and configure TAP interface
  - Calls `get_tap()` to open tun
  - Calls `set_ipv4_addr()` to assign `192.168.100.1`
  - Calls `activate_tap()` to bring interface up
- `get_tap()` - Open TUN/TAP device, configure as TAP, return fd
- `set_ipv4_addr(name, ip)` - Use ioctl to assign IPv4 address
- `activate_tap(fd)` - Set `IFF_UP` flag

---

## Packet Flow

### **Incoming (RX)**
```
TAP device
    ↓ (raw bytes)
start_listening() allocates struct pkt
    ↓
send_up_to_ethernet()
    ↓
ethernet.receive_frame_up()
    ├─ (EtherType 0x0806) → arp.receive_arp_up()
    │   └─ (ARP Request) → arp.create_arp_response()
    │       └─ send_arp_down() → ethernet.send_frame_down()
    │           └─ write_to_tap()
    │
    └─ (EtherType 0x0800) → ipv4.receive_ipv4_up()
        ├─ (Protocol 1) → icmp.receive_icmp_up()
        ├─ (Protocol 6) → tcp.receive_tcp_up()
        └─ (Protocol 17) → udp.receive_udp_up()
```

### **Outgoing (TX)**
```
Upper Layer → send_down()
    ↓
Lower Layer adds header, updates offset
    ↓
... (cascading down)
    ↓
ethernet.send_frame_down() adds MAC header
    ↓
tap.write_to_tap() writes to /dev/net/tun
    ↓
TAP device (kernel forwards to network)
```

---

## Key Design Decisions

| Aspect | Design | Notes |
|--------|--------|-------|
| **Packet Modification** | In-place when possible | ARP response reuses request packet |
| **Layer Routing** | By protocol ID/EtherType | Fast lookup without string matching |
| **Memory Model** | Heap-allocated packets | Supports async processing |
| **Offset Tracking** | Per-packet offset | Avoids header stripping/copying |
| **Data Immutability** | Mostly const (can modify for ARP) | Comment in types.h acknowledges this |

---

## Known Issues & TODOs

1. **Memory Management:**
   - `free(buffer)` in `tap.c` after `rcv_up()` - use-after-free risk
   - No cleanup of `packet` and `packet->metadata` in downstream layers

2. **Layer Lookup:**
   - Linear search through `ups[]`/`downs[]` arrays inefficient

3. **Offset Handling:**
   - Not subtracting lower-layer header lengths when sending down

4. **Incomplete Implementations:**
   - IPv4, ICMP, TCP, UDP are stubs (return 0)
   - No actual packet processing in these layers

5. **Error Handling:**
   - Some functions don't return proper error codes
   - TAP write errors close fd but don't handle cleanup

---

## Build & Run

```bash
make          # Compile to build/networking.elf
make clean    # Remove build artifacts
./build/networking.elf  # Run (requires root for TAP)
```