const std = @import("std");
// const network = @import("network");

const vnc = @import("vnc");

pub fn main(init: std.process.Init) !u8 {
    // try network.init();
    // defer network.deinit();

    const io = init.io;

    var stream = try std.Io.net.HostName.connect(
        try .init("localhost"),
        io,
        5900,
        .{ .protocol = .tcp, .mode = .stream },
    );
    defer stream.close(io);

    var read_buffer: [1024]u8 = undefined;
    var stream_reader = stream.reader(io, &read_buffer);
    const reader: *std.Io.Reader = &stream_reader.interface;
    var write_buffer: [1024]u8 = undefined;
    var stream_writer = stream.writer(io, &write_buffer);
    const writer: *std.Io.Writer = &stream_writer.interface;

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
