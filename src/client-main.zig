const std = @import("std");
const network = @import("network");

const vnc = @import("vnc");

pub fn main() !u8 {
    var socket = try network.connectToHost(std.heap.page_allocator, "localhost", 5900, .tcp);
    defer socket.close();

    const reader = socket.reader();
    // const writer = socket.writer();

    var server_version_str: [12]u8 = undefined;
    try reader.readNoEof(&server_version_str);

    const server_version = try vnc.ProtocolVersion.parse(server_version_str);

    if (server_version.major != 3 and server_version.minor != 8) {
        return 1;
    }

    return 0;
}
