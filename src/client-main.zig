const std = @import("std");
const network = @import("network");

const vnc = @import("vnc");

pub fn main() !u8 {
    try network.init();
    defer network.deinit();

    var socket = try network.connectToHost(std.heap.page_allocator, "localhost", 5900, .tcp);
    defer socket.close();

    var read_buffer: [1024]u8 = undefined;
    var sock_reader = socket.reader(&read_buffer);
    const reader: *std.Io.Reader = &sock_reader.interface;
    var write_buffer: [1024]u8 = undefined;
    var sock_writer = socket.writer(&write_buffer);
    const writer: *std.Io.Writer = &sock_writer.interface;
    // const writer = socket.writer();

    var server_version_str: [12]u8 = undefined;
    try reader.readSliceAll(&server_version_str);

    const server_version = try vnc.ProtocolVersion.parse(server_version_str);

    std.debug.print("{}\n", .{server_version});

    if (server_version.major != 3 or server_version.minor != 8) {
        return 1;
    }

    try writer.writeAll(&server_version_str);
    try writer.flush();

    return 0;
}
