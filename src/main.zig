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

    while (try server.waitEvent()) |event| {
        switch (event) {
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

        // Initialization phase
        const shared_connection = blk: {
            const shared_flag = try reader.readByte(); // 0 => disconnect others, 1 => share with others

            try writer.writeIntBig(u16, properties.screen_width); // width
            try writer.writeIntBig(u16, properties.screen_height); // height
            try PixelFormat.bgrx8888.serialize(writer); // pixel format, 16 byte

            try writer.writeIntBig(u32, desktop_name_len); // virtual desktop name len
            try writer.writeAll(properties.desktop_name); // virtual desktop name bytes

            break :blk (shared_flag != 0);
        };

        return Server{
            .socket = sock,
            .temp_memory = std.ArrayListAligned(u8, 16).init(allocator),

            .protocol_version = protocol_version,
            .shared_connection = shared_connection,
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
        _ = pf;
        _ = buf;
        _ = color;
    }

    pub fn decode(pf: PixelFormat, encoded: []const u8) Color {
        _ = pf;
        _ = encoded;
    }
};

pub const Color = struct {
    r: u8,
    g: u8,
    b: u8,
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
