# PANDORA'S BOX - PROTOCOL ANALYSIS REPORT

## Executive Summary
Successfully analyzed the custom "Pandora" protocol communication from the provided PCAP file. The protocol follows the documented specification with initialization, encrypt requests, and encrypt responses.

## Communication Details

### 🎯 **Target Communication Stream**
- **Client**: `10.1.0.217:42455`
- **Server**: `10.1.0.20:60123`
- **Protocol**: Custom Pandora encryption protocol
- **Total Data**: 422 bytes client → server, 164 bytes server → client

---

## Protocol Analysis

### 1. **Initialization Message (Client → Server)**
```
Field: N (Number of Requests)
Value: 5 encrypt requests
Format: 4-byte integer in network byte order
Hex: 0x00000005
```

### 2. **Encrypt Requests (Client → Server)**
The client sent **5 encrypt requests**, each with the structure:

| Request # | Check Value | Length | Data Content |
|-----------|-------------|---------|--------------|
| 1 | `0x0417` (1047) | 88 bytes | Base64 fragment #1 |
| 2 | `0x0417` (1047) | 72 bytes | Base64 fragment #2 |
| 3 | `0x0417` (1047) | 107 bytes | Base64 fragment #3 |
| 4 | `0x0417` (1047) | 87 bytes | Base64 fragment #4 |
| 5 | `0x0417` (1047) | 34 bytes | Base64 fragment #5 |

**🔍 Key Observations:**
- **Consistent Check Value**: All requests use `0x0417` (1047) for integrity verification
- **Fragmented Data**: The data is a single Base64-encoded message split across 5 requests
- **Variable Length**: Each request contains a different amount of data

### 3. **Reconstructed Data**
When the 5 Base64 fragments are concatenated and decoded:

**Original Base64 (383 characters):**
```
TkNMLUZKQ0ctMTYzMiBOQ0wtRkpDRy0xNjMyIE5DTC1GSkNHLTE2MzIgTkNMLUZKQ0ctMTYzMiBOQ0wtRkpDRy0xNjMyIE5DTC1GSkNHLTE2MzIgTkNMLUZKQ0ctMTYzMiBOQ0wtRkpDRy0xNjMyIE5DTC1GSkNHLTE2MzIgTkNMLUZKQ0ctMTYzMiBOQ0wtRkpDRy0xNjMyIE5DTC1GSkNHLTE2MzIgTkNMLUZKQ0ctMTYzMiBOQ0wtRkpDRy0xNjMyIE5DTC1GSkNHLTE2MzIgTkNMLUZKQ0ctMTYzMiBOQ0wtRkpDRy0xNjMyIE5DTC1GSkNHLTE2MzIgTkNMLUZKQ0ctMTYzMiBOQ0wtRkpDRy0xNjMyIE5DTC1GSkN
```

**🔓 Decoded Message (287 bytes):**
```
NCL-FJCG-1632 NCL-FJCG-1632 NCL-FJCG-1632 NCL-FJCG-1632 NCL-FJCG-1632 NCL-FJCG-1632 NCL-FJCG-1632 NCL-FJCG-1632 NCL-FJCG-1632 NCL-FJCG-1632 NCL-FJCG-1632 NCL-FJCG-1632 NCL-FJCG-1632 NCL-FJCG-1632 NCL-FJCG-1632 NCL-FJCG-1632 NCL-FJCG-1632 NCL-FJCG-1632 NCL-FJCG-1632 NCL-FJCG-1632 NCL-FJC
```

### 4. **Encrypt Response (Server → Client)**
```
Response Length: 160 bytes
Hash Count: 5 SHA-256 hashes (32 bytes each)
Total Response: 164 bytes (4-byte length + 160-byte hash data)
```

**🔐 Extracted SHA-256 Hashes:**
```
Hash #1: b8c97b08e198fa9ff79a3a9c1f0109b18687b7a1a3ff1772c29b4dc86753d711
Hash #2: 8817153ae81d94b5d6c745e63d1df31d5d02bd3b030b820c3c038654fdca619c
Hash #3: f8f9e772e1d42c5a327c0fec4101eca5a27b6d93b1d2102db5a37ebd52e34305
Hash #4: f5efdbdcfa80e9c0b9af155f6273ba997cbd3e4afddad2a950dfb9f786c564f7
Hash #5: 6a48c4295ef0fa5f9bfed8283a700b63fef2054686e97874096b1c2bc0d96ec4
```

---

## 🔍 Analysis & Findings

### **Message Content**
The decoded message reveals the repeated string: **`NCL-FJCG-1632`**
- This appears to be an identifier, code, or flag
- **NCL** could be "National Cyber League" or similar organization
- **FJCG-1632** appears to be a specific identifier or event code

### **Protocol Behavior**
1. ✅ **Follows Documentation**: The communication strictly adheres to the provided protocol specification
2. ✅ **Integrity Verification**: Consistent check value (0x0417) across all requests
3. ✅ **Proper Response**: Server returned exactly 5 hashes for 5 requests
4. ✅ **Correct Hash Format**: SHA-256 hashes (32 bytes each) as expected

### **Security Observations**
- **Data Fragmentation**: Message split across multiple requests (possibly for evasion or protocol design)
- **Base64 Encoding**: Standard encoding, not encryption (data was readable once decoded)
- **Hash Generation**: Server performs cryptographic hashing of client data
- **Network Protocol**: Uses TCP for reliable delivery

---

## 🎯 **Key Findings Summary**

| Field | Value |
|-------|--------|
| **Client IP** | 10.1.0.217 |
| **Server IP** | 10.1.0.20 |
| **Protocol** | Custom Pandora encryption service |
| **Requests Sent** | 5 encrypt requests |
| **Check Value** | 0x0417 (1047) |
| **Message** | `NCL-FJCG-1632` (repeated 20 times) |
| **Hash Algorithm** | SHA-256 |
| **Hashes Returned** | 5 complete hashes |
| **Total Communication** | 586 bytes (422 + 164) |

---

## 🏁 **Conclusion**

The Pandora protocol analysis successfully:
1. ✅ **Decoded the custom protocol** according to specifications
2. ✅ **Extracted the hidden message**: `NCL-FJCG-1632`
3. ✅ **Captured all cryptographic hashes** returned by the server
4. ✅ **Verified protocol integrity** with consistent check values
5. ✅ **Demonstrated complete communication flow** from initialization to response

The hackers were using this custom protocol to transmit data to an encryption service, which processed their requests and returned SHA-256 hashes. The repeated identifier "NCL-FJCG-1632" suggests this may be related to a cybersecurity challenge or competition.

**🔓 The mystery of Pandora's Box has been opened and decoded! 📦✨**