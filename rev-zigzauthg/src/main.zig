const std = @import("std");
const linux = std.os.linux;

const rip_offset = 16;
const len = 28;
var exception_count: u32 = 0;

const chunk_products = [7]u32{ 49841568, 38760000, 37620000, 67581290, 38670320, 47516040, 41367375 };
const chunk_thirds_res = [7]u32{ 1588, 1607, 1621, 1642, 1585, 1641, 1570 };
const chunk_starts = [7][]const u8{ "TH", "d0", "_K", "w_", "g_", "nG", "g3" };

fn sigill_handler(signo: i32, siginfo: *const linux.siginfo_t, ucontext: ?*anyopaque) callconv(.c) void {
    _ = siginfo;

    if (signo == linux.SIG.ILL) {
        if (ucontext) |ctx| {
            const ctx_cast: *linux.ucontext_t = @ptrCast(@alignCast(ctx));
            ctx_cast.mcontext.gregs[rip_offset] += 2;

            exception_count += 1;
        }
    }
}

fn banner() !void {
    const stdout = std.io.getStdOut().writer();

    try stdout.print("+-------------------------------------------+\n", .{});
    try stdout.print("|            Restricted Access              |\n", .{});
    try stdout.print("|                     -                     |\n", .{});
    try stdout.print("|         Authentication Required           |\n", .{});
    try stdout.print("+-------------------------------------------+\n", .{});
    try stdout.print("\n", .{});
}

fn check_login(login: []const u8) bool {
    const wanted = "TeerthdwhSceSao";
    for (0..login.len) |i| {
        const login_idx = (2 * i) % login.len;
        if (login[login_idx] != wanted[i]) {
            return false;
        }
    }
    return true;
}

fn char_product(seq: []const u8) u32 {
    var res: u32 = 1;
    for (seq) |elt| {
        res *= elt;
    }

    return res;
}

fn char_sum(seq: []const u8) u32 {
    var sum: u32 = 0;
    for (seq) |elt| {
        sum += elt;
    }
    return sum;
}

fn check_chunk(seq: []const u8, sum_login: u32, idx: usize) bool {
    // Check seq length
    if (seq.len != 4) {
        return false;
    }

    // Check 2 first chars of seq
    if (!std.mem.eql(u8, seq[0..2], chunk_starts[idx])) {
        return false;
    }

    // Check third char
    if ((seq[2] ^ exception_count) + sum_login != chunk_thirds_res[idx]) {
        return false;
    }

    // Test last char
    return char_product(seq) == chunk_products[idx];
}

pub fn main() !void {
    const stderr = std.io.getStdErr().writer();
    const stdout = std.io.getStdOut().writer();
    const stdin = std.io.getStdIn().reader();

    var sigact: linux.Sigaction = undefined;
    sigact.flags = linux.SA.SIGINFO;
    sigact.handler.sigaction = sigill_handler;

    if (linux.sigaction(linux.SIG.ILL, &sigact, null) != 0) {
        try stderr.print("sigaction() failed\n", .{});
        linux.exit(1);
    }

    asm volatile ("ud2");

    try banner();

    // Read login
    try stdout.print("+-------------------------------------------+\n", .{});
    try stdout.print("| Login: ", .{});

    var login_buffer: [64]u8 = undefined;
    const login = stdin.readUntilDelimiter(&login_buffer, '\n') catch "";
    try stdout.print("+-------------------------------------------+\n", .{});

    asm volatile ("ud2");

    if (!check_login(login)) {
        try stderr.print("Bad login, who are you ?\n", .{});
        linux.exit(1);
    }

    asm volatile ("ud2");

    try stdout.print("+-------------------------------------------+\n", .{});
    try stdout.print("| Passphrase: ", .{});

    // Read passphrase
    var passphrase_buffer: [64]u8 = undefined;
    const secret_phrase = stdin.readUntilDelimiter(&passphrase_buffer, '\n') catch "";
    try stdout.print("+-------------------------------------------+\n", .{});

    asm volatile ("ud2");

    const sum_login = char_sum(login);
    var state: u32 = 0;
    var i: usize = 0;
    while (i < secret_phrase.len) : (i += 4) {
        var chunk: []const u8 = undefined;
        if (i + 4 < secret_phrase.len) {
            chunk = secret_phrase[i .. i + 4];
        } else {
            chunk = secret_phrase[i..secret_phrase.len];
        }

        if (!check_chunk(chunk, sum_login, i / 4)) {
            break;
        }

        asm volatile ("ud2");
        const product = char_product(chunk);
        state ^= product;
    }

    if (state == 73590429 and i == len) {
        try stdout.print("\nPsst.. Did you know \"The Jester\" himself created the last challenge of Reverse ?\n - What do you mean, this is not an important, secret information ?? Whatever, you found my flag anyway..\n", .{});
    } else {
        const answers = [5][]const u8{ "Viktor, you forgot the passphrase again...\n", "Damn Viktor, you are supposed to REMEMBER your password!\n", "You are UNBELIEVABLE Viktor !\n", "I thought you were Viktor \"The Secret Shadow\", not \"The Butcher\" and his 0 braincells...\n", "You know, don't bother trying cryptography if you can't remember a simple password\n" };
        var seed: u64 = undefined;
        try std.posix.getrandom(std.mem.asBytes(&seed));
        var prng = std.Random.DefaultPrng.init(seed);

        const i_rand = prng.random().int(usize) % answers.len;
        try stdout.print("{s}", .{answers[i_rand]});
    }
}
