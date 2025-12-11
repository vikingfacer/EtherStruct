//! This  module provides structures and functions to work with network packets
//! by converting bytes into packed structures for Ethernet, IP, TCP, UDP

const std = @import("std");
const testing = std.testing;

/// returns Packed Size of type
///
/// item: type of item
/// returns: packed size of item
pub fn packedSize(item: anytype) comptime_int {
    return @bitSizeOf(item) / 8;
}

/// Apply function to struct fields
///
/// T: struct type
/// func: function applied to field
/// d: pointer to struct
/// returns: void
fn compApplyToStruct(comptime T: type, func: anytype, d: *T) void {
    inline for (std.meta.fields(T)) |f| {
        if (@bitSizeOf(f.type) % 8 == 0) {
            @field(d, f.name) = func(f.type, @field(d, f.name));
        }
    }
}

/// Serializes bytes to native value
///
/// T: struct type
/// bytes: network bytes
/// returns: T with set fields in Native order
pub fn toNativeValue(comptime T: type, bytes: []const u8) T {
    var structReturned: T = undefined;

    @memmove(std.mem.asBytes(&structReturned)[0..packedSize(T)], bytes[0..packedSize(T)]);
    compApplyToStruct(T, std.mem.bigToNative, &structReturned);

    return structReturned;
}

/// Deserializes bytes to network bytes
///
/// T: struct type
/// nativeStruct: struct containing data
/// returns: Network order bytes
pub fn toNetworkBytes(comptime T: type, nativeStruct: T) []const u8 {
    var bytes: T = nativeStruct;
    compApplyToStruct(T, std.mem.nativeToBig, &bytes);
    return std.mem.toBytes(bytes)[0 .. @bitSizeOf(T) / 8];
}

/// Ethernet frame type enum
pub const EthFrametype = enum(u16) {
    IPv4 = 0x0800,
    ARP = 0x0806,
    _,
};

/// Ethernet frame structure
pub const ethFrame = packed struct {
    dst: u48,
    src: u48,
    frameType: u16,
};

/// IP Protocol type enum
pub const ipProtocol = enum(u8) {
    ICMP = 0x01,
    TCP = 0x06,
    UDP = 0x11,
    _,
};

/// IP fragmentation flag
const flags = enum(u3) {
    Reserved,
    DoNotFragment,
    MoreFragments,
};

/// truncates u16 to u3 for IP fragmentation flag
///
/// frag: fragmentation bytes
/// return: u3: fragmentation flag value
fn fragmentFlags(frag: u16) u3 {
    return @truncate(frag >> 13);
}

/// truncates u16 to u13 for IP fragmentation offset
///
/// frag: fragmentation bytes
/// return: u13: fragmentation offset
fn fragmentOffset(frag: u16) u13 {
    return @truncate(frag);
}

/// IP header struct
pub const ipHeader = packed struct {
    length: u4,
    version: u4,
    DSCP: u6,
    ECN: u2,
    totalLength: u16,
    identification: u16,
    fragment: u16,
    ttl: u8,
    protocol: u8,
    checksum: u16,
    source: u32,
    destination: u32,
};

pub fn ipchecksum(buf: []u16) u16 {
    var accumulator: u16 = 0;
    for (buf) |b| {
        const add = @addWithOverflow(accumulator, b);
        accumulator = add[0] + add[1];
    }
    return accumulator;
}

test "ipchecksumZeros" {
    var zeros = [_]u16{0} ** 10;
    try testing.expect(ipchecksum(&zeros) == 0);
}

const tcpFlags = packed struct {
    CWR: u1,
    ECE: u1,
    URG: u1,
    ACK: u1,
    PSH: u1,
    RST: u1,
    SYN: u1,
    FIN: u1,
};

pub const tcpHeader = packed struct {
    srcPort: u16,
    dstPort: u16,
    seqNum: u32,
    ackNum: u32,
    reserved: u4,
    dataOffset: u4,
    flags: u8,
    windowSize: u16,
    checkSum: u16,
    urgentPrt: u16,
};

test "TCP header no options size == 20" {
    try testing.expect(@bitSizeOf(tcpHeader) / 8 == 20);
}

const udpHeader = struct {
    srcPort: u16,
    dstPort: u16,
    legnth: u16,
    checksum: u16,
};

//Frame 166: 66 bytes on wire (528 bits), 66 bytes captured (528 bits) on interface wlp4s0, id 0
//Ethernet II, Src: Intel_c9:6f:0d (18:5e:0f:c9:6f:0d), Dst: TpLinkPte_ed:d3:14 (dc:62:79:ed:d3:14)
//    Destination: TpLinkPte_ed:d3:14 (dc:62:79:ed:d3:14)
//        Address: TpLinkPte_ed:d3:14 (dc:62:79:ed:d3:14)
//        .... ..0. .... .... .... .... = LG bit: Globally unique address (factory default)
//        .... ...0 .... .... .... .... = IG bit: Individual address (unicast)
//    Source: Intel_c9:6f:0d (18:5e:0f:c9:6f:0d)
//        Address: Intel_c9:6f:0d (18:5e:0f:c9:6f:0d)
//        .... ..0. .... .... .... .... = LG bit: Globally unique address (factory default)
//        .... ...0 .... .... .... .... = IG bit: Individual address (unicast)
//    Type: IPv4 (0x0800)
//Internet Protocol Version 4, Src: 192.168.0.24, Dst: 142.250.64.106
//    0100 .... = Version: 4
//    .... 0101 = Header Length: 20 bytes (5)
//    Differentiated Services Field: 0x00 (DSCP: CS0, ECN: Not-ECT)
//    Total Length: 52
//    Identification: 0x999d (39325)
//    010. .... = Flags: 0x2, Don't fragment
//    ...0 0000 0000 0000 = Fragment Offset: 0
//    Time to Live: 64
//    Protocol: TCP (6)
//    Header Checksum: 0x1102 [validation disabled]
//    [Header checksum status: Unverified]
//    Source Address: 192.168.0.24
//    Destination Address: 142.250.64.106
//Transmission Control Protocol, Src Port: 40834, Dst Port: 443, Seq: 1, Ack: 204, Len: 0
//    Source Port: 40834
//    Destination Port: 443
//    [Stream index: 6]
//    [Conversation completeness: Incomplete (12)]
//    [TCP Segment Len: 0]
//    Sequence Number: 1    (relative sequence number)
//    Sequence Number (raw): 2176726243
//    [Next Sequence Number: 1    (relative sequence number)]
//    Acknowledgment Number: 204    (relative ack number)
//    Acknowledgment number (raw): 3660135843
//    1000 .... = Header Length: 32 bytes (8)
//    Flags: 0x010 (ACK)
//    Window: 696
//    [Calculated window size: 696]
//    [Window size scaling factor: -1 (unknown)]
//    Checksum: 0xc0d1 [unverified]
//    [Checksum Status: Unverified]
//    Urgent Pointer: 0
//    Options: (12 bytes), No-Operation (NOP), No-Operation (NOP), Timestamps
//        TCP Option - No-Operation (NOP)
//        TCP Option - No-Operation (NOP)
//        TCP Option - Timestamps: TSval 2807897796, TSecr 834059146
//            Kind: Time Stamp Option (8)
//            Length: 10
//            Timestamp value: 2807897796
//            Timestamp echo reply: 834059146
//    [Timestamps]
//    [SEQ/ACK analysis]
//        [This is an ACK to the segment in frame: 165]
//        [The RTT to ACK the segment was: 0.040872581 seconds]

const TCPAckBytes = [_]u8{
    0xdc, 0x62, 0x79, 0xed, 0xd3, 0x14, 0x18, //
    0x5e, 0x0f, 0xc9, 0x6f, 0x0d, 0x08, 0x00, //
    0x45, 0x00, 0x00, 0x34, 0x99, 0x9d, 0x40, //
    0x00, 0x40, 0x06, 0x11, 0x02, 0xc0, 0xa8, //
    0x00, 0x18, 0x8e, 0xfa, 0x40, 0x6a, 0x9f, //
    0x82, 0x01, 0xbb, 0x81, 0xbe, 0x34, 0xe3, //
    0xda, 0x29, 0x3d, 0xa3, 0x80, 0x10, 0x02, //
    0xb8, 0xc0, 0xd1, 0x00, 0x00, 0x01, 0x01, //
    0x08, 0x0a, 0xa7, 0x5d, 0x1e, 0xc4, 0x31, //
    0xb6, 0xbb, 0x8a,
};

test "Ethernet header size == " {
    try testing.expect(packedSize(ethFrame) == 14);
}

test "Ethernet Frame" {
    const localhostEth = TCPAckBytes[0..packedSize(ethFrame)];

    const eth = toNativeValue(ethFrame, localhostEth);

    try testing.expectEqual(0xdc6279edd314, eth.dst);
    try testing.expectEqual(0x0185e0fc96f0d, eth.src);
    try testing.expect(0x0800 == eth.frameType);

    try testing.expectEqualSlices(u8, localhostEth, toNetworkBytes(ethFrame, eth));
}

test "IP header size == 20" {
    try testing.expect(packedSize(ipHeader) == 20);
}

test "IP header" {
    const ipBytes = TCPAckBytes[packedSize(ethFrame) .. packedSize(ethFrame) + packedSize(ipHeader)];
    const iphdr = toNativeValue(ipHeader, ipBytes);
    try std.testing.expectEqual(iphdr.version, 4);

    const IHL: u32 = iphdr.length;
    try std.testing.expectEqual(IHL * 32 / 8, 20);
    try std.testing.expectEqual(iphdr.DSCP, 0);
    try std.testing.expectEqual(iphdr.ECN, 0);
    try std.testing.expectEqual(iphdr.totalLength, 52);
    try std.testing.expectEqual(iphdr.identification, 0x999d);
    try std.testing.expectEqual(fragmentFlags(iphdr.fragment), 0x2);
    try std.testing.expectEqual(fragmentOffset(iphdr.fragment), 0x0);
    try std.testing.expectEqual(iphdr.ttl, 64);
    try std.testing.expectEqual(iphdr.protocol, @intFromEnum(ipProtocol.TCP));
    try std.testing.expectEqual(iphdr.checksum, 0x1102);

    // try std.testing.expectEqual(0x0, ipchecksum(@ptrCast(@alignCast(@constCast(&TCPAckBytes[0 .. packedSize(ethFrame) + packedSize(ipHeader)])))));
    try std.testing.expectEqualSlices(u8, ipBytes, toNetworkBytes(ipHeader, iphdr));
}

test "TCP header" {
    const preTCP = packedSize(ethFrame) + packedSize(ipHeader);
    const tcpBytes = TCPAckBytes[preTCP .. preTCP + packedSize(tcpHeader)];
    const tcpHdr = toNativeValue(tcpHeader, tcpBytes);
    try std.testing.expectEqual(40834, tcpHdr.srcPort);
    try std.testing.expectEqual(443, tcpHdr.dstPort);
    try std.testing.expectEqual(2176726243, tcpHdr.seqNum);
    try std.testing.expectEqual(3660135843, tcpHdr.ackNum);
    try std.testing.expectEqual(0, tcpHdr.reserved);
    try std.testing.expectEqual(8, tcpHdr.dataOffset);
    try std.testing.expectEqual(0x010, tcpHdr.flags);
    try std.testing.expectEqual(696, tcpHdr.windowSize);
    try std.testing.expectEqual(0xc0d1, tcpHdr.checkSum);
    try std.testing.expectEqual(0, tcpHdr.urgentPrt);
}

test "UDP header" {
    // User Datagram Protocol, Src Port: 54435, Dst Port: 36176
    // Source Port: 54435
    // Destination Port: 36176
    // Length: 45
    // Checksum: 0x0000 [zero-value ignored]
    // UDP payload (37 bytes)

    const udpBytes = [_]u8{ 0xd4, 0xa3, 0x8d, 0x50, 0x00, 0x2d, 0x00, 0x00 };
    const udpHdr = toNativeValue(udpHeader, &udpBytes);
    try std.testing.expectEqual(54435, udpHdr.srcPort);
    try std.testing.expectEqual(36176, udpHdr.dstPort);
    try std.testing.expectEqual(45, udpHdr.legnth);
}
