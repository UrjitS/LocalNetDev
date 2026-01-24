# Local-Net
Local Net proposes the design and implementation of a decentralized, peer-to-peer communications system for Internet of Things (IoT) devices leveraging Bluetooth-based mesh networking. The system integrates three core technical components, a custom communications protocol with frame structures supporting fragmentation and multiple control message types, a dynamic mesh routing algorithm with quality-based path selection and self-healing capabilities, and an end-to-end encryption standard combining X25519 key exchange, AES-128-CTR encryption, and HMAC-SHA256 authentication. This architecture enables devices to share data securely without relying on centralized infrastructure or internet connectivity, addressing critical vulnerabilities in current IoT systems where dependency on cloud infrastructure and single gateways creates points of failure that render devices inoperable when connectivity is lost.

Local Net will be implemented in C on the BlueZ Bluetooth stack for Linux-based systems, with development following an Agile methodology across five milestones spanning 24 weeks. The system supports multiple node types (full nodes, edge nodes, and gateway nodes) with dynamic route discovery that automatically adapts to topology changes and node failures through heartbeat monitoring and route recalculation. Security is ensured through session-based encryption with frame counter management to prevent replay attacks and automatic key rotation upon frame counter overflow to maintain long term security.

The expected outcomes include a fully functional secure mesh networking system capable of mult-hop communication. Local Net aims to support IoT applications in remote operations, disaster recovery, industrial automation, and other situations where secure, resilient, and autonomous device-to-device communication is critical. By creating a self-healing, scalable mesh network, this project contributes a practical solution to the growing need for decentralized IoT infrastructure that maintains functionality independent of centralized services.

## Resources
https://people.csail.mit.edu/albert/bluez-intro/index.html

## File Structure
```
The filestructure for the project looks like the following: 
├── .gitignore               
├── CMakeLists.txt                 
├── README.md
├── encryption/
│   ├── encryption.c
│   └── encryption.h
├── protocol/
│   ├── protocol.c
│   └── protocol.h
├── routing/
│   ├── routing.c
│   └── routing.h
├── tests/
│   ├── test_protocol.c
│   └── test_routing.c
├── utils/
│   ├── utils.c
│   └── utils.h
└── LICENSE
```

## Building
### Building Prerequisites
The following prerequisite is required:
* Bluetooth
* GLib 2.0
* bluez_inc
```
sudo apt-get install libbluetooth-dev
sudo apt install -y libglib2.0-dev
```

### How do setup bluez_inc
The bluez_inc library is an interface to BlueZ, without needing to use DBus commands. This project uses the library for 
the underlying Bluetooth implementation. Before running these commands make sure GLib 2.0 is installed.

```
git clone https://github.com/weliem/bluez_inc.git
cd ./bluez_inc
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=$HOME/.local
cmake --build build --target install
```

### Building the project
To build the application use the following commands:
```
cd Local-Net/
mkdir build && cd build/
cmake ..
make all
```

## How to Run
### Running Local Net
To run the program use the command ```./LocalNet```

### Running the Test Cases
#### Running Protocol Implementation Test Cases
To run the protocol implementation test cases use the command ```./protocol_tests```

#### Running Routing Implementation Test Cases
To run the routing implementation test cases use the command ```./routing_tests```