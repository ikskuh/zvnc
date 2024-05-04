const std = @import("std");
const network = @import("network");

const vnc = @import("vnc.zig");

pub fn main() anyerror!void {
    var server_sock = try network.Socket.create(.ipv4, .tcp);
    defer server_sock.close();

    try server_sock.enablePortReuse(true);
    try server_sock.bindToPort(5959);

    try server_sock.listen();

    std.debug.print("waiting for client...\n", .{});

    const client = try server_sock.accept();

    var server = try Server.open(std.heap.page_allocator, client, .{
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

                try server.sendFramebufferUpdate(&[_]UpdateRectangle{
                    UpdateRectangle{
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

pub const ServerProperties = struct {
    desktop_name: []const u8,
    screen_width: u16,
    screen_height: u16,
};

const Server = struct {
    socket: network.Socket,
    temp_memory: std.ArrayListAligned(u8, 16),

    // public api:

    protocol_version: vnc.ProtocolVersion,
    shared_connection: bool,
    pixel_format: vnc.PixelFormat,

    pub fn open(allocator: std.mem.Allocator, sock: network.Socket, properties: ServerProperties) !Server {
        errdefer sock.close();

        const desktop_name_len =  std.math.cast(u32, properties.desktop_name.len) orelse return error.Overflow;

        var writer = sock.writer();
        var reader = sock.reader();

        // Initial handshake
        const protocol_version = blk: {
            try writer.writeAll("RFB 003.008\n"); // RFB Version 3.8

            var handshake: [12]u8 = undefined;
            try reader.readNoEof(&handshake);

            break :blk try vnc.ProtocolVersion.parse(handshake);
        };

        // Security handshake. We are insecure.
        {
            try writer.writeByte(1); // number of types
            try writer.writeByte(@intFromEnum(vnc.Security.none)); // "no security"

            const selected_security = std.meta.intToEnum(vnc.Security, try reader.readByte()) catch return error.ProtocolMismatch;

            std.debug.print("client security: {}\n", .{selected_security});

            const authentication_good = switch (selected_security) {
                .none => true,
                .vnc_authentication => blk: {
                    var challenge: [16]u8 = undefined;
                    std.crypto.random.bytes(&challenge);
                    try writer.writeAll(&challenge);

                    // The client encrypts the challenge with DES, using a password supplied
                    // by the user as the key. To form the key, the password is truncated
                    // to eight characters, or padded with null bytes on the right. The
                    // client then sends the resulting 16-byte response:

                    var response: [16]u8 = undefined;
                    try reader.readNoEof(&response);

                    // TODO: Implement a proper DES verification

                    break :blk std.mem.eql(u8, &response, "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00");
                },
                else => return error.ProtocolMismatch,
            };

            if (authentication_good) {
                try writer.writeIntBig(u32, 0); // handshake OK
            } else {
                try writer.writeIntBig(u32, 1); // handshake failed

                const error_message = "Hello World!";

                try writer.writeIntBig(u32, error_message.len);
                try writer.writeAll(error_message);

                // We failed to handle the client connection, but
                // this is a "successful" state.
                return error.AuthenticationFailed;
            }
        }

        var pixel_format = vnc.PixelFormat.bgrx8888;

        // Initialization phase
        const shared_connection = blk: {
            const shared_flag = try reader.readByte(); // 0 => disconnect others, 1 => share with others

            try writer.writeIntBig(u16, properties.screen_width); // width
            try writer.writeIntBig(u16, properties.screen_height); // height
            try pixel_format.serialize(writer); // pixel format, 16 byte

            try writer.writeIntBig(u32, desktop_name_len); // virtual desktop name len
            try writer.writeAll(properties.desktop_name); // virtual desktop name bytes

            break :blk (shared_flag != 0);
        };

        return Server{
            .socket = sock,
            .temp_memory = std.ArrayListAligned(u8, 16).init(allocator),

            .protocol_version = protocol_version,
            .shared_connection = shared_connection,
            .pixel_format = pixel_format,
        };
    }

    pub fn close(self: *Server) void {
        self.temp_memory.deinit();
        self.socket.close();
        self.* = undefined;
    }

    pub fn waitEvent(self: *Server) !?ClientEvent {
        var reader = self.socket.reader();

        const message_byte = reader.readByte() catch |err| switch (err) {
            error.EndOfStream => return null,
            else => |e| return e,
        };

        const message_type = std.meta.intToEnum(vnc.ClientMessageType, message_byte) catch return error.ProtocolViolation;
        switch (message_type) {
            .set_pixel_format => {
                var padding: [3]u8 = undefined;
                try reader.readNoEof(&padding);

                const pf = try vnc.PixelFormat.deserialize(reader);
                self.pixel_format = pf; // update the current pixel format
                return ClientEvent{ .set_pixel_format = pf };
            },
            .set_encodings => {
                var padding: [1]u8 = undefined;
                try reader.readNoEof(&padding);

                const num_encodings = try reader.readIntBig(u16);

                try self.temp_memory.resize(@sizeOf(vnc.Encoding) * num_encodings);

                const encodings = @as([*]vnc.Encoding, @ptrCast(self.temp_memory.items.ptr))[0..num_encodings];

                var i: usize = 0;
                while (i < num_encodings) : (i += 1) {
                    encodings[i] = @as(vnc.Encoding, @enumFromInt(try reader.readIntBig(i32)));
                }

                return ClientEvent{ .set_encodings = encodings };
            },
            .framebuffer_update_request => {
                const incremental = try reader.readByte();
                const x_pos = try reader.readIntBig(u16);
                const y_pos = try reader.readIntBig(u16);
                const width = try reader.readIntBig(u16);
                const height = try reader.readIntBig(u16);

                return ClientEvent{
                    .framebuffer_update_request = .{
                        .incremental = (incremental != 0),
                        .x = x_pos,
                        .y = y_pos,
                        .width = width,
                        .height = height,
                    },
                };
            },
            .key_event => {
                const down_flag = try reader.readByte();

                var padding: [2]u8 = undefined;
                try reader.readNoEof(&padding);

                const key = @as(vnc.Key, @enumFromInt(try reader.readIntBig(u32)));

                return ClientEvent{
                    .key_event = .{ .key = key, .down = (down_flag != 0) },
                };
            },
            .pointer_event => {
                const button_mask = try reader.readByte();
                const x_pos = try reader.readIntBig(u16);
                const y_pos = try reader.readIntBig(u16);

                return ClientEvent{
                    .pointer_event = .{ .x = x_pos, .y = y_pos, .buttons = button_mask },
                };
            },
            .client_cut_text => {
                var padding: [3]u8 = undefined;
                try reader.readNoEof(&padding);

                const msg_length = try reader.readIntBig(u32);

                try self.temp_memory.resize(msg_length);

                try reader.readNoEof(self.temp_memory.items);

                return ClientEvent{
                    .client_cut_text = self.temp_memory.items,
                };
            },
            // else => {
            //     std.debug.print("unhandled message type: {}\n", .{message_type});

            //     var seq: [4096]u8 = undefined;
            //     const len = try reader.read(&seq);
            //     if (len == 0)
            //         break;

            //     std.debug.print("received: {}\n", .{
            //         std.fmt.fmtSliceEscapeUpper(seq[0..len]),
            //     });
            // },
        }
    }

    pub fn sendFramebufferUpdate(self: *Server, rectangles: []const UpdateRectangle) !void {
        const num_rects =  std.math.cast(u16, rectangles.len) orelse return error.Overflow;

        var buffered_writer = std.io.bufferedWriter(self.socket.writer());
        const writer = buffered_writer.writer();
        try writer.writeByte(@intFromEnum(vnc.ServerMessageType.framebuffer_update));
        try writer.writeByte(0); // padding

        try writer.writeIntBig(u16, num_rects);

        for (rectangles) |rect| {
            try writer.writeIntBig(u16, rect.x);
            try writer.writeIntBig(u16, rect.y);
            try writer.writeIntBig(u16, rect.width);
            try writer.writeIntBig(u16, rect.height);
            try writer.writeIntBig(i32, @intFromEnum(rect.encoding));
            try writer.writeAll(rect.data);
        }

        try buffered_writer.flush();
    }

    /// Changes entries in the clients color map.
    /// - `first` is the first color entry to change.
    /// - `colors` is a slice of colors that will be written to the client color map at the offset `first`.
    pub fn sendSetColorMapEntries(self: *Server, first: u16, colors: []const vnc.Color) !void {
        const color_count = try std.math.cast(u16, colors.len);

        var writer = self.socket.writer();
        try writer.writeByte(@intFromEnum(vnc.ServerMessageType.set_color_map_entries));
        try writer.writeByte(0); // padding

        try writer.writeIntBig(u16, first);
        try writer.writeIntBig(u16, color_count);

        for (colors) |c| {
            try writer.writeIntBig(u16, @as(u16, @intFromFloat(std.math.maxInt(u16) * std.math.clamp(c.r, 0.0, 1.0))));
            try writer.writeIntBig(u16, @as(u16, @intFromFloat(std.math.maxInt(u16) * std.math.clamp(c.g, 0.0, 1.0))));
            try writer.writeIntBig(u16, @as(u16, @intFromFloat(std.math.maxInt(u16) * std.math.clamp(c.b, 0.0, 1.0))));
        }
    }

    /// Rings a signal on the viewer if possible.
    pub fn sendBell(self: *Server) !void {
        var writer = self.socket.writer();
        try writer.writeByte(@intFromEnum(vnc.ServerMessageType.bell));
    }

    /// Sets the new clipboard content of the viewer.
    /// - `text` is the ISO 8859-1 (Latin-1) encoded text.
    pub fn sendServerCutText(self: *Server, text: []const u8) !void {
        const length = std.math.cast(u32, text.len) orelse return error.Overflow;

        var writer = self.socket.writer();
        try writer.writeByte(@intFromEnum(vnc.ServerMessageType.server_cut_text));
        try writer.writeByte(0); // padding
        try writer.writeByte(0); // padding
        try writer.writeByte(0); // padding
        try writer.writeIntBig(u32, length);
        try writer.writeAll(text);
    }
};

pub const UpdateRectangle = struct {
    x: u16,
    y: u16,
    width: u16,
    height: u16,
    encoding: vnc.Encoding,
    data: []const u8,
};

pub const ClientEvent = union(vnc.ClientMessageType) {
    set_pixel_format: vnc.PixelFormat,
    set_encodings: []const vnc.Encoding,
    framebuffer_update_request: FramebufferUpdateRequest,
    key_event: KeyEvent,
    pointer_event: PointerEvent,
    client_cut_text: []const u8,

    pub const FramebufferUpdateRequest = struct {
        incremental: bool,
        x: u16,
        y: u16,
        width: u16,
        height: u16,
    };
    pub const KeyEvent = struct {
        key: vnc.Key,
        down: bool,
    };
    pub const PointerEvent = struct {
        x: u16,
        y: u16,
        buttons: u8,
    };
};

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
