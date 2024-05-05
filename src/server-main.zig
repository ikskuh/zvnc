const std = @import("std");
const network = @import("network");

const vnc = @import("vnc");

pub fn main() anyerror!void {
    var server_sock = try network.Socket.create(.ipv4, .tcp);
    defer server_sock.close();

    try server_sock.enablePortReuse(true);
    try server_sock.bindToPort(5900);

    try server_sock.listen();

    std.debug.print("waiting for client...\n", .{});

    const client = try server_sock.accept();

    var server = try vnc.Server.open(std.heap.page_allocator, client, .{
        .screen_width = 320,
        .screen_height = 240,
        .desktop_name = "Virtual Desktop",
    });
    defer server.close();

    std.debug.print("protocol version:  {}\n", .{server.protocol_version});
    std.debug.print("shared connection: {}\n", .{server.shared_connection});

    const start = std.time.nanoTimestamp();

    while (try server.waitEvent()) |event| {
        switch (event) {
            .set_pixel_format => {}, // use internal handler

            .framebuffer_update_request => |req| {
                var fb = std.ArrayList(u8).init(std.heap.page_allocator);
                defer fb.deinit();

                const now = std.time.nanoTimestamp();

                const delta = @as(f32, @floatFromInt(now - start)) / std.time.ns_per_s;

                var y: usize = 0;
                while (y < req.height) : (y += 1) {
                    var x: usize = 0;
                    while (x < req.width) : (x += 1) {
                        const px = x + req.x;
                        const py = y + req.y;

                        const c: vnc.Color = .{
                            .r = @as(f32, @floatFromInt(px)) / 319.0,
                            .g = @as(f32, @floatFromInt(py)) / 239.0,
                            .b = @mod(delta, 1.0),
                        };

                        var buf: [8]u8 = undefined;
                        const bits = server.pixel_format.encode(&buf, c);
                        try fb.appendSlice(bits);
                    }
                }

                try server.sendFramebufferUpdate(&[_]vnc.UpdateRectangle{
                    .{
                        .x = req.x,
                        .y = req.y,
                        .width = req.width,
                        .height = req.height,
                        .encoding = .raw,
                        .data = fb.items,
                    },
                });
            },

            .key_event => |ev| {
                if (ev.key == @as(vnc.Key, @enumFromInt(' '))) {
                    try server.sendBell();
                } else if (ev.key == .@"return") {
                    try server.sendServerCutText("HELLO, WORLD!");
                }
            },

            else => std.debug.print("received unhandled event: {}\n", .{event}),
        }
    }
}

// pub fn encodeRectangle(framebuffer: anytype, encoding: Encoding, writer: anytype) !void {
//     switch (encoding) {
//         .raw => {},
//         .copy_rect => {},
//         .rre => {},
//         .hextile => {},
//         .trle => {},
//         .zrle => {},
//         .cursor_pseudo_encoding => return error.UnsupportedEncoding,
//         .desktop_size_pseudo_encoding => return error.UnsupportedEncoding,
//     }
// }
