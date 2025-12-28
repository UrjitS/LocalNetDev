# Local-Net
Local Net proposes the design and implementation of a decentralized, peer-to-peer communications system for Internet of Things (IoT) devices leveraging Bluetooth-based mesh networking. The system integrates three core technical components, a custom communications protocol with frame structures supporting fragmentation and multiple control message types, a dynamic mesh routing algorithm with quality-based path selection and self-healing capabilities, and an end-to-end encryption standard combining X25519 key exchange, AES-128-CTR encryption, and HMAC-SHA256 authentication. This architecture enables devices to share data securely without relying on centralized infrastructure or internet connectivity, addressing critical vulnerabilities in current IoT systems where dependency on cloud infrastructure and single gateways creates points of failure that render devices inoperable when connectivity is lost.

Local Net will be implemented in C on the BlueZ Bluetooth stack for Linux-based systems, with development following an Agile methodology across five milestones spanning 24 weeks. The system supports multiple node types (full nodes, edge nodes, and gateway nodes) with dynamic route discovery that automatically adapts to topology changes and node failures through heartbeat monitoring and route recalculation. Security is ensured through session-based encryption with frame counter management to prevent replay attacks and automatic key rotation upon frame counter overflow to maintain long term security.

The expected outcomes include a fully functional secure mesh networking system capable of mult-hop communication. Local Net aims to support IoT applications in remote operations, disaster recovery, industrial automation, and other situations where secure, resilient, and autonomous device-to-device communication is critical. By creating a self-healing, scalable mesh network, this project contributes a practical solution to the growing need for decentralized IoT infrastructure that maintains functionality independent of centralized services.

## Features

### Milestone 3: Routing Algorithm Implementation (Complete)

- **Route Discovery Protocol**: Complete route request/reply mechanism with hop count tracking, reverse/forward path construction, and intermediate node handling
- **Packet Forwarding Engine**: TTL-based forwarding with routing table lookups, next-hop determination, and error handling
- **Self-Healing Mechanisms**: Heartbeat monitoring, automatic route recalculation, and connection state recovery

## Resources
https://people.csail.mit.edu/albert/bluez-intro/index.html

## File Structure
```
├── .gitignore               
├── CMakeLists.txt                 
├── README.md
├── main.c                    # Example application demonstrating API usage
├── bluetooth/
│   ├── bluetooth_transport.c # BlueZ Bluetooth transport layer
│   └── bluetooth_transport.h
├── mesh/
│   ├── mesh_network.c        # High-level mesh networking API
│   └── mesh_network.h
├── encryption/
│   ├── encryption.c
│   └── encryption.h
├── protocol/
│   ├── protocol.c            # Protocol serialization/deserialization
│   └── protocol.h
├── routing/
│   ├── routing.c             # Routing tables, route discovery, forwarding
│   └── routing.h
├── tests/
│   ├── test_protocol.c
│   ├── test_routing.c
│   └── test_mesh_routing.c   # Milestone 3 comprehensive tests
├── utils/
│   ├── utils.c
│   └── utils.h
└── LICENSE
```

## Building

### Prerequisites
```bash
sudo apt-get install libbluetooth-dev
```

### Build Commands
```bash
cd Local-Net/
mkdir build && cd build/
cmake ..
make all
```

### Running Tests
```bash
cd build/
ctest --output-on-failure
```

Or run individual test suites:
```bash
./routing_tests
./mesh_routing_tests
./protocol_tests
```

## How to Run

### Usage
```
./LocalNet [node_type] [command] [args...]
```

### Node Types
- `edge` - Edge node (limited routing, low power)
- `full` - Full node (full routing capabilities)  
- `gateway` - Gateway node (bridges to external networks)

### Commands
- `scan` - Scan for nearby Bluetooth devices
- `listen` - Listen for incoming messages
- `send <hex_id> <message>` - Send message to specific device
- `broadcast <message>` - Broadcast to all neighbors
- `status` - Print network status
- `routes` - Print routing table
- `connections` - Print connection table
- `discover <hex_id>` - Discover route to device
- `demo` - Run interactive demo

### Examples
```bash
# Start as a full node in listen mode
./LocalNet full listen

# Start as edge node and send a message
./LocalNet edge send 0x12345678 "Hello World"

# Run the interactive demo as a gateway
./LocalNet gateway demo
```

## API Usage for Developers

LocalNet provides a simple API for building mesh networking applications:

```c
#include "mesh/mesh_network.h"

// Initialize the mesh network
struct mesh_network *network = mesh_network_init(FULL_NODE);

// Set up callbacks
mesh_set_message_callback(network, on_message_received, user_data);
mesh_set_node_joined_callback(network, on_node_joined);

// Start the network
mesh_network_start(network);

// Send messages
mesh_send_message(network, destination_id, data, len);

// Query network status
int neighbors = mesh_get_connection_count(network);
bool has_route = mesh_has_route(network, destination_id);

// Cleanup
mesh_network_shutdown(network);
```

See `main.c` for a complete example implementation.

## Testing

The project includes comprehensive tests for Milestone 3 deliverables:

### Route Discovery Protocol Tests
- Route request creation and serialization
- Intermediate node processing
- Destination node processing
- Route reply creation and processing
- Hop count tracking

### Packet Forwarding Engine Tests
- TTL-based forwarding
- Routing table lookups
- Next-hop determination
- Unreachable destination handling
- Local packet processing

### Self-Healing Mechanism Tests
- Heartbeat monitoring and reset
- Route recalculation on expiry
- Connection timeout detection
- Connection state recovery
- Route invalidation on neighbor loss

### Integration Tests
- Multi-hop route discovery
- Self-healing route invalidation
- Packet serialization round-trip
- Link quality based routing
- Discovery timing logic

## License
See LICENSE file.

