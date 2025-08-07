const std = @import("std");
const testing = std.testing;

// want print to be as indexed and to and from bytes to be as in memory
fn printUint(writer: anytype, comptime T: type, sixOctets: T) !void {
    const bytes = std.mem.asBytes(&sixOctets);
    const bitSize = @bitSizeOf(T) / 8;
    var delimiter: u8 = ':';
    for (0..bitSize) |i| {
        if (i == (bitSize - 1)) {
            delimiter = ' ';
        }
        try writer.print("{x}{c}", .{ bytes[i], delimiter });
    }
}

pub const EthFrametype = enum(u16) {
    IPv4 = 0x0800,
    ARP = 0x0806,
    _,
};

///
///compile time apply to struct
///
fn compApplyToStruct(T: anytype, func: anytype, d: *T) void {
    inline for (std.meta.fields(T)) |f| {
        if (@bitSizeOf(f.type) % 8 == 0) {
            @field(d, f.name) = func(f.type, @field(d, f.name));
        }
    }
}

pub const ethFrame = packed struct {
    dst: u48,
    src: u48,
    frameType: u16,

    //    pub fn fromBytes(data: []const u8) ethFrame {
    //        var eth = std.mem.bytesToValue(ethFrame, data);
    //        compApplyToStruct(ethFrame, std.mem.bigToNative, &eth);
    //        return eth;
    //    }
    //
    //    pub fn toBytes(eth: *ethFrame) []const u8 {
    //        compApplyToStruct(ethFrame, std.mem.nativeToBig, eth);
    //        // struct is packed need to trim the end
    //        return std.mem.asBytes(eth)[0 .. @bitSizeOf(ethFrame) / 8];
    //    }

    pub fn format(
        self: ethFrame,
        comptime fmt: []const u8,
        options: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        _ = fmt;
        _ = options;
        try writer.print("source: ", .{});
        try printUint(writer, u48, self.src);
        try writer.print("destination: ", .{});
        try printUint(writer, u48, self.dst);
        const asBytes = std.mem.asBytes(&self.frameType);
        try writer.print("type: 0x{x}{x}", .{ asBytes[0], asBytes[1] });
    }
};

test "From Bytes" {
    const localhostEth =
        [_]u8{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00 };
    const eth = ethFrame.fromBytes(&localhostEth);

    try testing.expect(eth.dst == 0x0);
    try testing.expect(eth.src == 0x0);
    try testing.expect(eth.frameType == 0x800);
}

test "Ethernet header size == " {
    try testing.expect(@bitSizeOf(ethFrame) / 8 == 14);
}
const test_allocator = std.testing.allocator;
test "Ethernet Format test" {
    const macAddr: u48 = 0xaabbccddeeff;
    const frameType: u16 = 0x1234;
    const eframe: ethFrame = .{ .dst = macAddr, .src = macAddr, .frameType = frameType };
    const eframeStr = try std.fmt.allocPrint(test_allocator, "{}", .{eframe});
    defer test_allocator.free(eframeStr);

    try testing.expectEqualSlices(
        u8, //
        "source: 0xaabbccddeeff destination: 0xaabbccddeeff type: 0x1234", //
        eframeStr, //
    );
}

pub const icmpHeader = packed struct {
    icmpType: u8,
    code: u8,
    checksum: u16,
    roh: u32, //rest of header
    pub fn init(icmpType: u8, code: u8, checksum: u16, roh: u32) icmpHeader {
        return .{
            .icmpType = icmpType, //
            .code = code, //
            .checksum = std.mem.nativeToBig(u16, checksum), //
            .roh = std.mem.nativeToBig(u32, roh),
        };
    }
    pub fn format(
        self: icmpHeader,
        comptime fmt: []const u8,
        options: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        _ = fmt;
        _ = options;
        try writer.print("type: 0x{x}, code: 0x{x}, checksum: 0x{x}, roh: 0x{x}", //
            .{ self.icmpType, self.code, self.checksum, self.roh });
    }
};

test "icmp header format" {
    const icmp: icmpHeader = icmpHeader.init(0xff, 0xee, 0xaabb, 0xffeeffff);

    const icmpStr = try std.fmt.allocPrint(test_allocator, "{}", .{icmp});
    defer test_allocator.free(icmpStr);
    const expected = "type: 0xff, code: 0xee, checksum: 0xbbaa, roh: 0xffffeeff";
    try testing.expectEqualSlices(u8, icmpStr, expected);
}

pub const ping = packed struct {
    pingType: u8,
    code: u8,
    checksum: u16,
    identifier: u16,
    seqNum: u16,
    timeStamp: u64,
    pub fn init(
        pingType: u8,
        code: u8,
        checksum: u16,
        identifier: u16,
        seqNum: u16,
        timeStamp: u64,
    ) ping {
        return .{
            .pingType = pingType,
            .code = code,
            .checksum = checksum,
            .identifier = identifier,
            .seqNum = seqNum,
            .timeStamp = timeStamp,
        };
    }
    pub fn format(
        self: ping,
        comptime fmt: []const u8,
        options: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        _ = fmt;
        _ = options;
        try writer.print("pingtype: {x}, code: {x}, checksum: {x}, identifier: {x}, seqNum: {x}, timeStamp: {x}", //
            .{ self.pingType, self.code, self.checksum, self.identifier, self.seqNum, self.timeStamp });
    }
};

pub const ipProtocol = enum(u8) {
    ICMP = 0x01,
    TCP = 0x06,
    UDP = 0x11,
    _,
};

const flags = enum(u3) {
    Reserved,
    DoNotFragment,
    MoreFragments,
};

fn fragmentFlags(frag: u16) u3 {
    return @truncate(frag >> 13);
}

fn fragementOffset(frag: u16) u13 {
    return @truncate(frag);
}

pub const ipHeader = packed struct {
    // length needs to come first idk why
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

    //pub fn fromBytes(data: []const u8) ipHeader {
    //    var ip = std.mem.bytesToValue(ipHeader, data);
    //    compApplyToStruct(ipHeader, std.mem.bigToNative, &ip);
    //    return ip;
    //}

    //pub fn toBytes(ip: *ipHeader) []const u8 {
    //    compApplyToStruct(ipHeader, std.mem.nativeToBig, ip);
    //    // struct is packed need to trim the end
    //    return std.mem.asBytes(ip)[0 .. @bitSizeOf(ipHeader) / 8];
    //}

    pub fn format(
        self: ipHeader,
        comptime fmt: []const u8,
        options: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        _ = fmt;
        _ = options;

        try writer.print("0b{b:0>4} Version: {d:0>2}, ", .{ self.version, self.version });
        try writer.print("0b{b:0>4} Length: {d:0>2}, ", .{ self.length, self.length });
        try writer.print("0b{b:0>6} DSCP: {d:0>3}, ", .{ self.DSCP, self.DSCP });
        try writer.print("0b{b:0>1} ECN: {d:0>1}, ", .{ self.ECN, self.ECN });
        try writer.print("Total Length: {d}, ", .{self.totalLength});
        try writer.print("identification: (0x{x}) {d}, ", .{ self.identification, self.identification });
        try writer.print("Flags: 0x{x}, ", .{fragmentFlags(self.fragment)});
        try writer.print("Fragment Offset: 0x{x}, ", .{fragementOffset(self.fragment)});
        try writer.print("TTL: {d}, ", .{self.ttl});
        try writer.print("Protocol: {d}, ", .{self.protocol});
        try writer.print("Header Checksum: 0x{x}, ", .{self.checksum});
        const src = std.mem.asBytes(&self.source);
        try writer.print("Source Address: {d}.{d}.{d}.{d}, ", //
            .{ src[0], src[1], src[2], src[3] });
        const dst = std.mem.asBytes(&self.destination);
        try writer.print("Destination Address: {d}.{d}.{d}.{d}, ", //
            .{ dst[0], dst[1], dst[2], dst[3] });
    }
};

test "IP header size == 20" {
    try testing.expect(@bitSizeOf(ipHeader) / 8 == 20);
}
//Internet Protocol Version 4, Src: 192.168.1.122, Dst: 192.168.1.1
//    0100 .... = Version: 4
//    .... 0101 = Header Length: 20 bytes (5)
//    Differentiated Services Field: 0x00 (DSCP: CS0, ECN: Not-ECT)
//    Total Length: 84
//    Identification: 0x883a (34874)
//    010. .... = Flags: 0x2, Don't fragment
//        0... .... = Reserved bit: Not set
//        .1.. .... = Don't fragment: Set
//        ..0. .... = More fragments: Not set
//    ...0 0000 0000 0000 = Fragment Offset: 0
//    Time to Live: 64
//    Protocol: ICMP (1)
//    Header Checksum: 0x2ea3 [validation disabled]
//    [Header checksum status: Unverified]
//    Source Address: 192.168.1.122
//    Destination Address: 192.168.1.1

const ipBytes = [_]u8{
    0x45, 0x00, 0x00, 0x54, 0x88, 0x3a, 0x40, //
    0x00, 0x40, 0x01, 0x2e, 0xa3, 0xc0, 0xa8, //
    0x01, 0x7a, 0xc0, 0xa8, 0x01, 0x01,
};

test "IP header test" {
    var iphdr = ipHeader.fromBytes(&ipBytes);
    try std.testing.expectEqualStrings(&ipBytes, iphdr.toBytes());
}

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
    pub fn format(
        self: tcpHeader,
        comptime fmt: []const u8,
        options: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        _ = fmt;
        _ = options;
        writer.print("src: {}, dst: {}", .{ self.srcPort, self.dstPort });
    }
};

test "TCP header no options size == 20" {
    std.debug.print("size: {} \n", .{@bitSizeOf(tcpHeader) / 8});
    try testing.expect(@bitSizeOf(tcpHeader) / 8 == 20);
}

// Transmission Control Protocol, Src Port: 55950, Dst Port: 443, Seq: 1, Ack: 1, Len: 0
//     Source Port: 55950
//     Destination Port: 443
//     [Stream index: 0]
//     [Conversation completeness: Incomplete (4)]
//     [TCP Segment Len: 0]
//     Sequence Number: 1    (relative sequence number)
//     Sequence Number (raw): 1353731647
//     [Next Sequence Number: 1    (relative sequence number)]
//     Acknowledgment Number: 1    (relative ack number)
//     Acknowledgment number (raw): 1407010374
//     1000 .... = Header Length: 32 bytes (8)
//     Flags: 0x010 (ACK)
//     Window: 501
//     [Calculated window size: 501]
//     [Window size scaling factor: -1 (unknown)]
//     Checksum: 0xb34d [unverified]
//     [Checksum Status: Unverified]
//     Urgent Pointer: 0
//     Options: (12 bytes), No-Operation (NOP), No-Operation (NOP), Timestamps
//     [Timestamps]
