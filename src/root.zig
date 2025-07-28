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

pub const ethFrame = packed struct {
    dst: u48,
    src: u48,
    frameType: u16,

    pub fn init(dst: u48, src: u48, frameType: u16) ethFrame {
        return .{
            .dst = std.mem.nativeToBig(u48, dst), //
            .src = std.mem.nativeToBig(u48, src), //
            .frameType = std.mem.nativeToBig(u16, frameType),
        };
    }
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

test "Ethernet header size == " {
    try testing.expect(@bitSizeOf(ethFrame) / 8 == 14);
}
const test_allocator = std.testing.allocator;
test "Ethernet Format test" {
    const macAddr: u48 = 0xaabbccddeeff;
    const frameType: u16 = 0x1234;
    const eframe: ethFrame = ethFrame.init(macAddr, macAddr, frameType);
    const eframeStr = try std.fmt.allocPrint(test_allocator, "{}", .{eframe});
    defer test_allocator.free(eframeStr);

    try testing.expectEqualSlices(u8, eframeStr, //
        "source: aa:bb:cc:dd:ee:ff destination: aa:bb:cc:dd:ee:ff type: 0x1234");
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
        try writer.print("pingtype: {x}, code: {x}, checksum: {x}, identifier: {x}, seqNum: {x}, timeStamp: {x}", .{ self.pingType, self.code, self.checksum, self.identifier, self.seqNum, self.timeStamp });
    }
};

pub const ipHeader = packed struct {
    version: u4,
    length: u4,
    DSCP: u6,
    ECN: u2,
    totalLength: u16,
    identification: u16,
    flags: u3,
    FragmentOffset: u15,
    ttl: u8,
    protocol: u8,
    checksum: u16,
    source: u32,
    destination: u32,
    //pub fn format(
    //    self: ipHeader,
    //    comptime fmt: []const u8,
    //    options: std.fmt.FormatOptions,
    //    writer: anytype,
    //) !void {
    //    _ = fmt;
    //    _ = options;
    //}
};

test "IP header size == 20" {
    try testing.expect(@bitSizeOf(ipHeader) / 8 == 20);
}

pub const tcpHeader = packed struct {
    srcPort: u16,
    dstPort: u16,
    seqNum: u32,
    ackNum: u32,
    headerLength: u8,
    flags: u8,
    windowSize: u16,
    checkSum: u16,
    urgentPrt: u16,
    //pub fn format(
    //    self: tcpHeader,
    //    comptime fmt: []const u8,
    //    options: std.fmt.FormatOptions,
    //    writer: anytype,
    //) !void {
    //    _ = fmt;
    //    _ = options;
    //}
};

test "TCP header size == 20" {
    //try testing.expect(@sizeOf(tcpHeader) == 20);
}

pub fn hasOptions(self: tcpHeader) bool {
    var it_does: bool = false;
    if (self.headerLength > @bitSizeOf(tcpHeader)) {
        it_does = true;
    }
    return it_does;
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

pub fn fromBytes(comptime t: type, data: [*]u8) t {
    var data_slice: []u8 = undefined;
    data_slice.ptr = data;
    data_slice.len = @sizeOf(t);
    var layer: t = std.mem.bytesToValue(t, data[0..@sizeOf(t)]);
    std.mem.byteSwapAllFields(t, &layer);
    return layer;
}

pub fn toBytes(comptime t: type, data: anytype) []u8 {
    std.mem.byteSwapAllFields(t, data);
    return std.mem.asBytes(data);
}
