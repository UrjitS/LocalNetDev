# Communications Protocol Design
## Data Frame Structure
Header
(8 bytes)
Network
(8 bytes)
Payload
(Variable Length)
Security
(24 bytes)


### Header:
Name
Size
Description
Protocol Version
4 bits
Current protocol version.
Message Type
4 bits
Type of the message (Data, Control, Discovery, Ack, etc).
Fragmentation Flag
1 bit
Indication flag for if this message is part of a fragment.
Fragmentation Number
7 bits
The current fragment index.
Total Fragments
8 bits
The total fragments for the message.
Time To Live
8 bits
Max hop count.
Payload Length
16 bits
Size of payload.
Sequence Number
16 bits
Message sequence number.


### Network:
Name
Size
Description
Source ID
32 bits
Origins device unique identifier.
Destination ID
32 bits
Destination device identifier.


### Payload:
The payload will be a maximum 200 bytes per fragment and will contain a plaintext or encrypted application data or control data.
Security:
Name
Size
Description
Frame Counter
4 bytes
Increasing counter to prevent replay attacks. Rollover triggers key rotation.
Nonce
8 bytes
Ensures unique Initialization Vector.
Message Authentication Code
12 bytes
Hash based message authentication code for integrity.


## Control Frame Structures
### Discovery Message
Discovery messages are sent out by nodes who haven't hit their threshold for available connections.
Name
Size
Description
Available Connections
1 bytes
The number of available connection spots this device has.
Timestamp
4 bytes
Timestamp of the message.



### Route Request
Route requests are issued by nodes seeking to find a path to a target node.
Name
Size
Description
Request ID
4 bytes
Randomly generated unique identifier.
Destination ID
4 bytes
Destination device identifier.
Hop Count
1 byte
Incremented by each node on the path to the destination.
Reverse path length
1 byte
Number of entries in reverse path.
Reverse Path
Variable
Each node adds their device's unique identifier to build the path taken till the destination.


### Route Reply
A route reply is the destination node replying back to the origin with the complete information.

Name
Size
Description
Request ID
4 bytes
Origins device unique identifier.
Route Cost
1 byte
Total hops taken to reach the destination node.
Forward path length
1 byte
Number of entries in the forward path.
Forward Path
Variable
All the nodes taken from the origin to reach the destination.


### Heartbeat
Name
Size
Description
Device Status
1 byte
The device's current status.
Active Connection Number
1 byte
The number of available connection spots this device has.
Timestamp
4 bytes
Timestamp of the heartbeat.



### Acknowledgement
Name
Size
Description
Acknowledgement sequence number
2 byte
The original message sequence number being acknowledged.
Status Code
1 byte
Status code of the acknowledgement.
Received fragment count
1 byte
The number of received fragments.
Received fragment list
Variable
The list of the received fragments.


### Key Exchange
Name
Size
Description
Public Key
32 bytes
Public key of this node.
Timestamp
4 bytes
Timestamp issued.



### Status Codes
This is the current list of status codes:

Code
Definition
0x00
Success
0x01
Route not found
0x02
Destination unreachable
0x03
TTL Expired
0x04
Authentication Failed
0x05
Fragmentation Error
0x06
Invalid Message


## Mesh Network Design
### Network Topology
Nodes in the network can take three different roles.

Full Node
Maintains routing tables
Forwards messages for other nodes and itself
Performs route discoveries
Has a higher maximum connections
Requires device to have more system resources and a connected power source

Edge Node
Limited routing capabilities
Typically sends/receives its own data
Lower maximum connections
Low power consumption and system resources required

Gateway Node
Connects the mesh to external networks (internet capable device)
Routes between mesh and internet networks
Maintains the same capabilities as a Full Node
### Connection Management
The following is the process for nodes in the mesh network to discover each other:

A new node broadcasts a Discovery Message every 30 seconds for 2 minutes and then every 5 minutes
Other node responds with their available connections
New node selects neighbors based off:
Signal strength where the Received Signal Strength (RSSI) is strong
Available connections spots
Establish a secure connection using the just works process

A connection table maintained by nodes can look like the following

Neighbor ID
RSSI
Link Quality
Last Seen
Connection Type
0x123456
-60
0.9
<Timestamp>
STABLE
0x123457
-70
0.5
<Timestamp>
DISCONNECTED


The Link Quality = (Successful Packets / Total Packets) for the last 100 transmissions

Connection states can be the following:
State
Definition
DISCOVERING
Initial neighbor discovery phase
CONNECTING
Establishing a connection
STABLE
Normal operations
DISCONNECTED
Connection lost



### Routing Algorithm
Routing Table Structure
The routing table structure can look like the following:

Destination ID
Next Hop
Hop Count
Route Cost
Last Updated
Expiry
0x123456
0x123457
4
1.3
<Timestamp>
500s
0x123457
0x123456
5
4.5
<Timestamp>
500s


The route cost is calculated as the Sum of each hop's quality. Hop Quality = 1 / Link Quality
Route Discovery Process
For nodes to find routes to other nodes the following process is taken:

Route Request Initiation
Node checks its existing routing table for the destination
If no route exists, create a Route Request
Sets the Request ID to a randomly generated value
Initializes the Hop Count to 0
Adds its own Device ID to the Reverse Path
Sends the Route Request to all of its connections

Intermediate Node Actions
If this node has already received this Request ID then it drops the packet
Increment Hop Count
Add its own Device ID to the reverse path
If the Destination ID is its own Device ID it sends a Route Reply
If it has the Destination ID in its Routing Table it sends a Route Reply using its cached route
If the Hop Count is less than the Max Hops it broadcasts the request to all neighbors except the sender
If the Hop Count is greater than Max Hops the request is dropped
Packet Forwarding
Packet forwarding has the following pseudo code

If destination id == device id
Process packet
Send Acknowledgement
Else
If TTL <= 0
Drop packet
Send 0x03 to source
Else
Decrement TTL
If device has route to destination id
Get best route
Forward to next hop
Else
Initiate route discovery

Self Healing Mechanisms
Heartbeat
For nodes to ensure their neighbors are still connected they can periodically send Heartbeats to direct neighbors and if the neighbor misses 3 consecutive heartbeats then it can be marked as Disconnected.
Route Recalculation
Periodically when a routing entry in the routing table is expired, the node can go through the route discovery process again to ensure it always has an accurate route.
E2E Encryption Design
The core algorithms used are the following:
Symmetric Encryption: AES-128-CTR
Symmetric Encryption
Lightweight for IoT devices
Parallel encryption/decryption
Message Authentication: HMAC-SHA256 (Truncated to 96 bits)
Used for Message Authentication
Key Exchange: Elliptic Curve Diffie-Hellman (X25519)
Establishes shared secrets
Session Key Exchange
For two nodes who want to establish secure communications the following process is performed:

Node A generates an ephemeral key pair (A_private, A_public) using X25519
Node A initiates a key exchange request with Node B
Node B receives request and generates their own key pair (B_private, B_public) using X25519
Node B sends a key exchange response to Node A
Both Node A and B compute shared secret
A computes X25519(A_private, B_public)
B computes X25519(B_private, A_public)
Both Node A and B derive session keys using HKDF
Master Key = HKDF(shared secret, “master”, 32)
Encryption Key = HKDF(master key, “encryption” || Source Device ID || Destination Device ID, 16)
Auth Key = HKDF(master key, “auth” || Source Device ID || Destination Device ID. 16)
Both nodes are ready for communications using EK, AK
Encryption and Decryption
Sending Encrypted Messages
The pseudo code for sending encrypted messages is the following:
send_encrypted_data(Destination ID, Application Data):

If destination id session doesn't exist or is expired
Perform key exchange
Else
Retrieve EK, AK, Frame Counter

Generate 7 byte Nonce
Create IV = Nonce || Frame Counter || 5 bytes
Encrypt payload using EK, IV, Application Data
Set MAC Input = Header || Network || Encrypted Payload || Frame Counter
Compute MAC using AK, MAC Input and truncate output for first 96 bytes

Assemble complete frame
Increment frame counter
If frame counter overflow
Schedule key rotation


Send frame

Receiving Encrypted Messages
receive_encrypted_message(frame):

Parse frame into Header, Network, Encrypted Payload, Security
If network.destination_id != device id
Forward message
Return
If session key source id doesn't exist
Drop message
Send error acknowledgement
Return
Else
Extract EK, AK, Next expected frame counter from session keys
If received counter is not expected counter
Drop message
Send error acknowledgement
Return
Set MAC Input = Header || Network || Encrypted Payload || Received Counter
Compute MAC = HMAC_SHA256(AK, MAC Input)
If Compute MAC isn't Security.MAC
Drop message
Send error acknowledgement
Return
// Decrypt payload
Set IV = Security.Nonce || Security.Frame Counter || 5 bytes
Set Application Data = AES_CTR_Decrypt(EK, IV, Encrypted Payload)
Update next expected frame counter in session keys
Process application data
Send Acknowledgement

