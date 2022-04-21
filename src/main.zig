const std = @import("std");
const network = @import("network");

pub fn main() anyerror!void {
    var server_sock = try network.Socket.create(.ipv4, .tcp);
    defer server_sock.close();

    try server_sock.enablePortReuse(true);
    try server_sock.bindToPort(5959);

    try server_sock.listen();

    std.debug.print("waiting for client...\n", .{});

    var client = try server_sock.accept();

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

                const delta = @intToFloat(f32, now - start) / std.time.ns_per_s;

                var y: usize = 0;
                while (y < req.height) : (y += 1) {
                    var x: usize = 0;
                    while (x < req.width) : (x += 1) {
                        var px = x + req.x;
                        var py = y + req.y;

                        var c = Color{
                            .r = @intToFloat(f32, px) / 319.0,
                            .g = @intToFloat(f32, py) / 239.0,
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
                if (ev.key == @intToEnum(Key, ' ')) {
                    try server.sendBell();
                } else if (ev.key == .@"return") {
                    try server.sendServerCutText("HELLO, WORLD!");
                }
            },

            else => std.debug.print("received unhandled event: {}\n", .{event}),
        }
    }
}

const ProtocolVersion = struct {
    major: u8,
    minor: u8,
};

pub const ServerProperties = struct {
    desktop_name: []const u8,
    screen_width: u16,
    screen_height: u16,
};

const Server = struct {
    socket: network.Socket,
    temp_memory: std.ArrayListAligned(u8, 16),

    // public api:

    protocol_version: ProtocolVersion,
    shared_connection: bool,
    pixel_format: PixelFormat,

    pub fn open(allocator: std.mem.Allocator, sock: network.Socket, properties: ServerProperties) !Server {
        errdefer sock.close();

        const desktop_name_len = try std.math.cast(u32, properties.desktop_name.len);

        var writer = sock.writer();
        var reader = sock.reader();

        // Initial handshake
        const protocol_version = blk: {
            try writer.writeAll("RFB 003.008\n"); // RFB Version 3.8

            var handshake: [12]u8 = undefined;
            try reader.readNoEof(&handshake);

            if (!std.mem.eql(u8, handshake[0..4], "RFB "))
                return error.ProtocolMismatch;
            if (handshake[7] != '.')
                return error.ProtocolMismatch;
            if (handshake[11] != '\n')
                return error.ProtocolMismatch;

            const major_version = std.fmt.parseInt(u8, handshake[4..7], 10) catch return error.ProtocolMismatch;
            const minor_version = std.fmt.parseInt(u8, handshake[8..11], 10) catch return error.ProtocolMismatch;

            break :blk ProtocolVersion{ .major = major_version, .minor = minor_version };
        };

        // Security handshake. We are insecure.
        {
            try writer.writeByte(1); // number of types
            try writer.writeByte(@enumToInt(Security.none)); // "no security"

            const selected_security = std.meta.intToEnum(Security, try reader.readByte()) catch return error.ProtocolMismatch;

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

        var pixel_format = PixelFormat.bgrx8888;

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

        const message_type = std.meta.intToEnum(ClientMessageType, message_byte) catch return error.ProtocolViolation;
        switch (message_type) {
            .set_pixel_format => {
                var padding: [3]u8 = undefined;
                try reader.readNoEof(&padding);

                const pf = try PixelFormat.deserialize(reader);
                self.pixel_format = pf; // update the current pixel format
                return ClientEvent{ .set_pixel_format = pf };
            },
            .set_encodings => {
                var padding: [1]u8 = undefined;
                try reader.readNoEof(&padding);

                const num_encodings = try reader.readIntBig(u16);

                try self.temp_memory.resize(@sizeOf(Encoding) * num_encodings);

                const encodings = @ptrCast([*]Encoding, self.temp_memory.items.ptr)[0..num_encodings];

                var i: usize = 0;
                while (i < num_encodings) : (i += 1) {
                    encodings[i] = @intToEnum(Encoding, try reader.readIntBig(i32));
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

                const key = @intToEnum(Key, try reader.readIntBig(u32));

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
        const num_rects = try std.math.cast(u16, rectangles.len);

        var buffered_writer = std.io.bufferedWriter(self.socket.writer());
        const writer = buffered_writer.writer();
        try writer.writeByte(@enumToInt(ServerMessageType.framebuffer_update));
        try writer.writeByte(0); // padding

        try writer.writeIntBig(u16, num_rects);

        for (rectangles) |rect| {
            try writer.writeIntBig(u16, rect.x);
            try writer.writeIntBig(u16, rect.y);
            try writer.writeIntBig(u16, rect.width);
            try writer.writeIntBig(u16, rect.height);
            try writer.writeIntBig(i32, @enumToInt(rect.encoding));
            try writer.writeAll(rect.data);
        }

        try buffered_writer.flush();
    }

    /// Changes entries in the clients color map.
    /// - `first` is the first color entry to change.
    /// - `colors` is a slice of colors that will be written to the client color map at the offset `first`.
    pub fn sendSetColorMapEntries(self: *Server, first: u16, colors: []const Color) !void {
        const color_count = try std.math.cast(u16, colors.len);

        var writer = self.socket.writer();
        try writer.writeByte(@enumToInt(ServerMessageType.set_color_map_entries));
        try writer.writeByte(0); // padding

        try writer.writeIntBig(u16, first);
        try writer.writeIntBig(u16, color_count);

        for (colors) |c| {
            try writer.writeIntBig(u16, @floatToInt(u16, std.math.maxInt(u16) * std.math.clamp(c.r, 0.0, 1.0)));
            try writer.writeIntBig(u16, @floatToInt(u16, std.math.maxInt(u16) * std.math.clamp(c.g, 0.0, 1.0)));
            try writer.writeIntBig(u16, @floatToInt(u16, std.math.maxInt(u16) * std.math.clamp(c.b, 0.0, 1.0)));
        }
    }

    /// Rings a signal on the viewer if possible.
    pub fn sendBell(self: *Server) !void {
        var writer = self.socket.writer();
        try writer.writeByte(@enumToInt(ServerMessageType.bell));
    }

    /// Sets the new clipboard content of the viewer.
    /// - `text` is the ISO 8859-1 (Latin-1) encoded text.
    pub fn sendServerCutText(self: *Server, text: []const u8) !void {
        const length = try std.math.cast(u32, text.len);

        var writer = self.socket.writer();
        try writer.writeByte(@enumToInt(ServerMessageType.server_cut_text));
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
    encoding: Encoding,
    data: []const u8,
};

pub const ClientEvent = union(ClientMessageType) {
    set_pixel_format: PixelFormat,
    set_encodings: []const Encoding,
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
        key: Key,
        down: bool,
    };
    pub const PointerEvent = struct {
        x: u16,
        y: u16,
        buttons: u8,
    };
};

pub const PixelFormat = struct {
    pub const bgrx8888 = PixelFormat{
        .bpp = 32,
        .depth = 24,
        .big_endian = 0,
        .true_color = 1,
        .red_max = 255,
        .green_max = 255,
        .blue_max = 255,
        .red_shift = 16,
        .green_shift = 8,
        .blue_shift = 0,
    };

    bpp: u8,
    depth: u8,
    big_endian: u8,
    true_color: u8,
    red_max: u16,
    green_max: u16,
    blue_max: u16,
    red_shift: u8,
    green_shift: u8,
    blue_shift: u8,

    pub fn serialize(self: PixelFormat, writer: anytype) !void {
        try writer.writeIntBig(u8, self.bpp);
        try writer.writeIntBig(u8, self.depth);
        try writer.writeIntBig(u8, self.big_endian);
        try writer.writeIntBig(u8, self.true_color);
        try writer.writeIntBig(u16, self.red_max);
        try writer.writeIntBig(u16, self.green_max);
        try writer.writeIntBig(u16, self.blue_max);
        try writer.writeIntBig(u8, self.red_shift);
        try writer.writeIntBig(u8, self.green_shift);
        try writer.writeIntBig(u8, self.blue_shift);
        try writer.writeAll("\x00\x00\x00"); // padding
    }

    pub fn deserialize(reader: anytype) !PixelFormat {
        var pf = PixelFormat{
            .bpp = try reader.readIntBig(u8),
            .depth = try reader.readIntBig(u8),
            .big_endian = try reader.readIntBig(u8),
            .true_color = try reader.readIntBig(u8),
            .red_max = try reader.readIntBig(u16),
            .green_max = try reader.readIntBig(u16),
            .blue_max = try reader.readIntBig(u16),
            .red_shift = try reader.readIntBig(u8),
            .green_shift = try reader.readIntBig(u8),
            .blue_shift = try reader.readIntBig(u8),
        };
        var padding: [3]u8 = undefined;
        try reader.readNoEof(&padding); // padding
        return pf;
    }

    pub fn encode(pf: PixelFormat, buf: *[8]u8, color: Color) []u8 {
        var encoded: u64 = 0;

        if (pf.true_color != 0) {
            encoded |= @floatToInt(u64, @intToFloat(f32, pf.red_max) * color.r) << @truncate(u6, pf.red_shift);
            encoded |= @floatToInt(u64, @intToFloat(f32, pf.green_max) * color.g) << @truncate(u6, pf.green_shift);
            encoded |= @floatToInt(u64, @intToFloat(f32, pf.blue_max) * color.b) << @truncate(u6, pf.blue_shift);
        } else {
            @panic("indexed color encoding not implemented yet");
        }

        const endianess = switch (pf.big_endian) {
            0 => std.builtin.Endian.Little,
            else => std.builtin.Endian.Big,
        };

        switch (pf.bpp) {
            8 => {
                const part = buf[0..1];
                std.mem.writeInt(u8, part, @truncate(u8, encoded), endianess);
                return part;
            },
            16 => {
                const part = buf[0..2];
                std.mem.writeInt(u16, part, @truncate(u16, encoded), endianess);
                return part;
            },
            24 => {
                const part = buf[0..3];
                std.mem.writeInt(u24, part, @truncate(u24, encoded), endianess);
                return part;
            },
            32 => {
                const part = buf[0..4];
                std.mem.writeInt(u32, part, @truncate(u32, encoded), endianess);
                return part;
            },
            64 => {
                const part = buf[0..8];
                std.mem.writeInt(u64, part, @truncate(u64, encoded), endianess);
                return part;
            },
            else => return buf[0..0],
        }
    }

    pub fn decode(pf: PixelFormat, encoded: []const u8) Color {
        _ = pf;
        _ = encoded;
    }
};

pub const Color = struct {
    r: f32,
    g: f32,
    b: f32,
};

pub const Security = enum(u8) {
    invalid = 0,
    none = 1,
    vnc_authentication = 2,
};

pub const ClientMessageType = enum(u8) {
    set_pixel_format = 0,
    set_encodings = 2,
    framebuffer_update_request = 3,
    key_event = 4,
    pointer_event = 5,
    client_cut_text = 6,
};

pub const ServerMessageType = enum(u8) {
    framebuffer_update = 0,
    set_color_map_entries = 1,
    bell = 2,
    server_cut_text = 3,
};

pub const Key = enum(u32) {

    // For most ordinary keys, the keysym is the same as the corresponding
    // ASCII value. For full details, see [XLIBREF] or see the header file
    // <X11/keysymdef.h> in the X Window System distribution. Some other
    // common keys are:
    back_space = 0xff08,
    tab = 0xff09,
    @"return" = 0xff0d,
    escape = 0xff1b,
    insert = 0xff63,
    delete = 0xffff,
    home = 0xff50,
    end = 0xff57,
    page_up = 0xff55,
    page_down = 0xff56,
    left = 0xff51,
    up = 0xff52,
    right = 0xff53,
    down = 0xff54,
    f1 = 0xffbe,
    f2 = 0xffbf,
    f3 = 0xffc0,
    f4 = 0xffc1,
    f5 = 0xffc2,
    f6 = 0xffc3,
    f7 = 0xffc4,
    f8 = 0xffc5,
    f9 = 0xffc6,
    f10 = 0xffc7,
    f11 = 0xffc8,
    f12 = 0xffc9,
    shift_left = 0xffe1,
    shift_right = 0xffe2,
    control_left = 0xffe3,
    control_right = 0xffe4,
    meta_left = 0xffe7,
    meta_right = 0xffe8,
    alt_left = 0xffe9,
    alt_right = 0xffea,

    _,
};

pub const Encoding = enum(i32) {
    raw = 0,
    copy_rect = 1,
    rre = 2,
    hextile = 5,
    trle = 15,
    zrle = 16,
    cursor_pseudo_encoding = -239,
    desktop_size_pseudo_encoding = -223,
    _,
};
