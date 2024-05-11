const aegis = @cImport(@cInclude("aegis.h"));
const std = @import("std");
const random = std.crypto.random;
const testing = std.testing;

const max_msg_len: usize = 1000;
const max_ad_len: usize = 1000;
const iterations = 50000;

test "aegis-128l - encrypt_detached oneshot" {
    try testing.expectEqual(aegis.aegis_init(), 0);

    inline for ([_]usize{ 16, 32 }) |mac_len| {
        var msg_buf: [max_msg_len]u8 = undefined;
        var msg2_buf: [msg_buf.len]u8 = undefined;
        var ad_buf: [max_ad_len]u8 = undefined;
        var c_buf: [msg_buf.len]u8 = undefined;
        var mac: [mac_len]u8 = undefined;

        random.bytes(&msg_buf);
        random.bytes(&ad_buf);

        for (0..iterations) |_| {
            const msg_len = random.intRangeAtMost(usize, 0, msg_buf.len);
            const msg = msg_buf[0..msg_len];
            var c = c_buf[0..msg_len];
            _ = &c;

            const ad_len = random.intRangeAtMost(usize, 0, ad_buf.len);
            const ad = &ad_buf[0..ad_len];

            var nonce: [aegis.aegis128l_NPUBBYTES]u8 = undefined;
            random.bytes(&nonce);
            var key: [aegis.aegis128l_KEYBYTES]u8 = undefined;
            random.bytes(&key);

            var ret = aegis.aegis128l_encrypt_detached(c.ptr, &mac, mac_len, msg.ptr, msg.len, ad.ptr, ad.len, &nonce, &key);
            try testing.expectEqual(ret, 0);

            var msg2 = msg2_buf[0..msg_len];
            _ = &msg2;
            ret = aegis.aegis128l_decrypt_detached(msg2.ptr, c.ptr, c.len, &mac, mac_len, ad.ptr, ad.len, &nonce, &key);
            try testing.expectEqual(ret, 0);
            try testing.expectEqualSlices(u8, msg, msg2);
        }
    }
}

test "aegis-256 - encrypt_detached oneshot" {
    try testing.expectEqual(aegis.aegis_init(), 0);

    inline for ([_]usize{ 16, 32 }) |mac_len| {
        var msg_buf: [max_msg_len]u8 = undefined;
        var msg2_buf: [msg_buf.len]u8 = undefined;
        var ad_buf: [max_ad_len]u8 = undefined;
        var c_buf: [msg_buf.len]u8 = undefined;
        var mac: [mac_len]u8 = undefined;

        random.bytes(&msg_buf);
        random.bytes(&ad_buf);

        for (0..iterations) |_| {
            const msg_len = random.intRangeAtMost(usize, 0, msg_buf.len);
            const msg = msg_buf[0..msg_len];
            var c = c_buf[0..msg_len];
            _ = &c;

            const ad_len = random.intRangeAtMost(usize, 0, ad_buf.len);
            const ad = &ad_buf[0..ad_len];

            var nonce: [aegis.aegis256_NPUBBYTES]u8 = undefined;
            random.bytes(&nonce);
            var key: [aegis.aegis256_KEYBYTES]u8 = undefined;
            random.bytes(&key);

            var ret = aegis.aegis256_encrypt_detached(c.ptr, &mac, mac_len, msg.ptr, msg.len, ad.ptr, ad.len, &nonce, &key);
            try testing.expectEqual(ret, 0);

            var msg2 = msg2_buf[0..msg_len];
            _ = &msg2;
            ret = aegis.aegis256_decrypt_detached(msg2.ptr, c.ptr, c.len, &mac, mac_len, ad.ptr, ad.len, &nonce, &key);
            try testing.expectEqual(ret, 0);
            try testing.expectEqualSlices(u8, msg, msg2);
        }
    }
}

test "aegis-128l - incremental encryption" {
    try testing.expectEqual(aegis.aegis_init(), 0);

    const mac_len: usize = 16;
    var msg_buf: [max_msg_len]u8 = undefined;
    var msg2_buf: [msg_buf.len]u8 = undefined;
    var ad_buf: [max_ad_len]u8 = undefined;
    var c_buf: [msg_buf.len]u8 = undefined;
    var c2_buf: [c_buf.len]u8 = undefined;
    var mac: [mac_len]u8 = undefined;

    random.bytes(&ad_buf);

    const msg_len = random.intRangeAtMost(usize, 0, msg_buf.len);

    for (&msg_buf, 0..) |*m, i| {
        m.* = @truncate(i);
    }

    const msg = msg_buf[0..msg_len];
    var c = c_buf[0..msg_len];
    _ = &c;
    var c2 = c2_buf[0..msg_len];
    _ = &c2;

    const ad_len = random.intRangeAtMost(usize, 0, ad_buf.len);
    const ad = ad_buf[0..ad_len];

    var nonce: [aegis.aegis256_NPUBBYTES]u8 = undefined;
    random.bytes(&nonce);
    var key: [aegis.aegis256_KEYBYTES]u8 = undefined;
    random.bytes(&key);

    var st: aegis.aegis128l_state = undefined;
    var written: usize = undefined;

    aegis.aegis128l_state_init(&st, ad.ptr, ad.len, &nonce, &key);

    var cx = c;

    const m0 = msg[0 .. msg.len / 3];
    const m1 = msg[msg.len / 3 .. 2 * msg.len / 3];
    const m2 = msg[2 * msg.len / 3 ..];

    var ret = aegis.aegis128l_state_encrypt_update(&st, cx.ptr, cx.len, &written, m0.ptr, m0.len);
    try testing.expectEqual(ret, 0);
    cx = cx[written..];

    ret = aegis.aegis128l_state_encrypt_update(&st, cx.ptr, cx.len, &written, m1.ptr, m1.len);
    try testing.expectEqual(ret, 0);
    cx = cx[written..];

    ret = aegis.aegis128l_state_encrypt_update(&st, cx.ptr, cx.len, &written, m2.ptr, m2.len);
    try testing.expectEqual(ret, 0);
    cx = cx[written..];

    ret = aegis.aegis128l_state_encrypt_detached_final(&st, cx.ptr, cx.len, &written, &mac, mac.len);
    try testing.expectEqual(ret, 0);
    cx = cx[written..];
    try testing.expectEqual(cx.len, 0);

    ret = aegis.aegis128l_encrypt_detached(c2.ptr, &mac, mac_len, msg.ptr, msg.len, ad.ptr, ad.len, &nonce, &key);
    try testing.expectEqual(ret, 0);

    try testing.expectEqualSlices(u8, c, c2);

    var msg2 = msg2_buf[0..msg_len];
    _ = &msg2;
    ret = aegis.aegis128l_decrypt_detached(msg2.ptr, c.ptr, c.len, &mac, mac_len, ad.ptr, ad.len, &nonce, &key);
    try testing.expectEqual(ret, 0);
    try testing.expectEqualSlices(u8, msg, msg2);
}

test "aegis-256 - incremental encryption" {
    try testing.expectEqual(aegis.aegis_init(), 0);

    const mac_len: usize = 16;
    var msg_buf: [max_msg_len]u8 = undefined;
    var msg2_buf: [msg_buf.len]u8 = undefined;
    var ad_buf: [max_ad_len]u8 = undefined;
    var c_buf: [msg_buf.len]u8 = undefined;
    var c2_buf: [c_buf.len]u8 = undefined;
    var mac: [mac_len]u8 = undefined;

    random.bytes(&ad_buf);

    const msg_len = random.intRangeAtMost(usize, 0, msg_buf.len);

    for (&msg_buf, 0..) |*m, i| {
        m.* = @truncate(i);
    }

    const msg = msg_buf[0..msg_len];
    var c = c_buf[0..msg_len];
    _ = &c;
    var c2 = c2_buf[0..msg_len];
    _ = &c2;

    const ad_len = random.intRangeAtMost(usize, 0, ad_buf.len);
    const ad = ad_buf[0..ad_len];

    var nonce: [aegis.aegis256_NPUBBYTES]u8 = undefined;
    random.bytes(&nonce);
    var key: [aegis.aegis256_KEYBYTES]u8 = undefined;
    random.bytes(&key);

    var st: aegis.aegis256_state = undefined;
    var written: usize = undefined;

    aegis.aegis256_state_init(&st, ad.ptr, ad.len, &nonce, &key);

    var cx = c;

    const m0 = msg[0 .. msg.len / 3];
    const m1 = msg[msg.len / 3 .. 2 * msg.len / 3];
    const m2 = msg[2 * msg.len / 3 ..];

    var ret = aegis.aegis256_state_encrypt_update(&st, cx.ptr, cx.len, &written, m0.ptr, m0.len);
    try testing.expectEqual(ret, 0);
    cx = cx[written..];

    ret = aegis.aegis256_state_encrypt_update(&st, cx.ptr, cx.len, &written, m1.ptr, m1.len);
    try testing.expectEqual(ret, 0);
    cx = cx[written..];

    ret = aegis.aegis256_state_encrypt_update(&st, cx.ptr, cx.len, &written, m2.ptr, m2.len);
    try testing.expectEqual(ret, 0);
    cx = cx[written..];

    ret = aegis.aegis256_state_encrypt_detached_final(&st, cx.ptr, cx.len, &written, &mac, mac.len);
    try testing.expectEqual(ret, 0);
    cx = cx[written..];
    try testing.expectEqual(cx.len, 0);

    ret = aegis.aegis256_encrypt_detached(c2.ptr, &mac, mac_len, msg.ptr, msg.len, ad.ptr, ad.len, &nonce, &key);
    try testing.expectEqual(ret, 0);

    try testing.expectEqualSlices(u8, c, c2);

    var msg2 = msg2_buf[0..msg_len];
    _ = &msg2;
    ret = aegis.aegis256_decrypt_detached(msg2.ptr, c.ptr, c.len, &mac, mac_len, ad.ptr, ad.len, &nonce, &key);
    try testing.expectEqual(ret, 0);
    try testing.expectEqualSlices(u8, msg, msg2);
}

test "aegis-256 - incremental encryption 2" {
    try testing.expectEqual(aegis.aegis_init(), 0);

    const mac_len: usize = 16;
    var msg: [633]u8 = undefined;
    var msg2: [msg.len]u8 = undefined;
    var ad: [10]u8 = undefined;
    var c: [msg.len + mac_len]u8 = undefined;
    var c2: [c.len]u8 = undefined;

    random.bytes(&ad);
    random.bytes(&msg);

    var nonce: [aegis.aegis256_NPUBBYTES]u8 = undefined;
    random.bytes(&nonce);
    var key: [aegis.aegis256_KEYBYTES]u8 = undefined;
    random.bytes(&key);

    var st: aegis.aegis256_state = undefined;
    var written: usize = undefined;

    aegis.aegis256_state_init(&st, &ad, ad.len, &nonce, &key);

    var cx: []u8 = c[0..];

    const m0 = msg[0..11];
    const m1 = msg[11 .. 11 + 21];
    const m2 = msg[11 + 21 .. 11 + 21 + 311];
    const m3 = msg[11 + 21 + 311 ..];

    var ret = aegis.aegis256_state_encrypt_update(&st, cx.ptr, cx.len, &written, m0.ptr, m0.len);
    try testing.expectEqual(ret, 0);
    cx = cx[written..];

    ret = aegis.aegis256_state_encrypt_update(&st, cx.ptr, cx.len, &written, m1.ptr, m1.len);
    try testing.expectEqual(ret, 0);
    cx = cx[written..];

    ret = aegis.aegis256_state_encrypt_update(&st, cx.ptr, cx.len, &written, m2.ptr, m2.len);
    try testing.expectEqual(ret, 0);
    cx = cx[written..];

    ret = aegis.aegis256_state_encrypt_update(&st, cx.ptr, cx.len, &written, m3.ptr, m3.len);
    try testing.expectEqual(ret, 0);
    cx = cx[written..];

    ret = aegis.aegis256_state_encrypt_final(&st, cx.ptr, cx.len, &written, mac_len);
    try testing.expectEqual(ret, 0);
    cx = cx[written..];
    try testing.expectEqual(cx.len, 0);

    ret = aegis.aegis256_encrypt(&c2, mac_len, &msg, msg.len, &ad, ad.len, &nonce, &key);
    try testing.expectEqual(ret, 0);

    try testing.expectEqualSlices(u8, &c, &c2);

    ret = aegis.aegis256_decrypt(&msg2, &c, c.len, mac_len, &ad, ad.len, &nonce, &key);
    try testing.expectEqual(ret, 0);
    try testing.expectEqualSlices(u8, &msg, &msg2);
}

test "aegis-128l - incremental decryption" {
    try testing.expectEqual(aegis.aegis_init(), 0);

    const mac_len: usize = 16;
    var msg_buf: [max_msg_len]u8 = undefined;
    var msg2_buf: [msg_buf.len]u8 = undefined;
    var ad_buf: [max_ad_len]u8 = undefined;
    var c_buf: [msg_buf.len]u8 = undefined;
    var mac: [mac_len]u8 = undefined;

    random.bytes(&ad_buf);

    const msg_len = random.intRangeAtMost(usize, 0, msg_buf.len);

    for (&msg_buf, 0..) |*m, i| {
        m.* = @truncate(i);
    }

    const msg = msg_buf[0..msg_len];
    var c = c_buf[0..msg_len];

    const ad_len = random.intRangeAtMost(usize, 0, ad_buf.len);
    const ad = ad_buf[0..ad_len];

    var nonce: [aegis.aegis256_NPUBBYTES]u8 = undefined;
    random.bytes(&nonce);
    var key: [aegis.aegis256_KEYBYTES]u8 = undefined;
    random.bytes(&key);

    var ret = aegis.aegis128l_encrypt_detached(c.ptr, &mac, mac_len, msg.ptr, msg.len, ad.ptr, ad.len, &nonce, &key);
    try testing.expectEqual(ret, 0);

    var st: aegis.aegis128l_state = undefined;
    var written: usize = undefined;

    const c0 = c[0 .. c.len / 3];
    const c1 = c[c.len / 3 .. 2 * c.len / 3];
    var c2 = c[2 * c.len / 3 ..];
    _ = &c2;

    var mx = msg2_buf[0..c.len];

    aegis.aegis128l_state_init(&st, ad.ptr, ad.len, &nonce, &key);

    ret = aegis.aegis128l_state_decrypt_detached_update(&st, mx.ptr, mx.len, &written, c0.ptr, c0.len);
    try testing.expectEqual(ret, 0);
    mx = mx[written..];

    ret = aegis.aegis128l_state_decrypt_detached_update(&st, mx.ptr, mx.len, &written, c1.ptr, c1.len);
    try testing.expectEqual(ret, 0);
    mx = mx[written..];

    ret = aegis.aegis128l_state_decrypt_detached_update(&st, mx.ptr, mx.len, &written, c2.ptr, c2.len);
    try testing.expectEqual(ret, 0);
    mx = mx[written..];

    ret = aegis.aegis128l_state_decrypt_detached_final(&st, mx.ptr, mx.len, &written, &mac, mac.len);
    try testing.expectEqual(ret, 0);
    mx = mx[written..];

    try testing.expectEqual(mx.len, 0);
    try testing.expectEqualSlices(u8, msg, msg2_buf[0..msg.len]);
}

test "aegis-256 - incremental decryption" {
    try testing.expectEqual(aegis.aegis_init(), 0);

    const mac_len: usize = 16;
    var msg_buf: [max_msg_len]u8 = undefined;
    var msg2_buf: [msg_buf.len]u8 = undefined;
    var ad_buf: [max_ad_len]u8 = undefined;
    var c_buf: [msg_buf.len]u8 = undefined;
    var mac: [mac_len]u8 = undefined;

    random.bytes(&ad_buf);

    const msg_len = random.intRangeAtMost(usize, 0, msg_buf.len);

    for (&msg_buf, 0..) |*m, i| {
        m.* = @truncate(i);
    }

    const msg = msg_buf[0..msg_len];
    var c = c_buf[0..msg_len];

    const ad_len = random.intRangeAtMost(usize, 0, ad_buf.len);
    const ad = ad_buf[0..ad_len];

    var nonce: [aegis.aegis256_NPUBBYTES]u8 = undefined;
    random.bytes(&nonce);
    var key: [aegis.aegis256_KEYBYTES]u8 = undefined;
    random.bytes(&key);

    var ret = aegis.aegis256_encrypt_detached(c.ptr, &mac, mac_len, msg.ptr, msg.len, ad.ptr, ad.len, &nonce, &key);
    try testing.expectEqual(ret, 0);

    var st: aegis.aegis256_state = undefined;
    var written: usize = undefined;

    var c0 = c[0 .. c.len / 3];
    _ = &c0;
    var c1 = c[c.len / 3 .. 2 * c.len / 3];
    _ = &c1;
    var c2 = c[2 * c.len / 3 ..];
    _ = &c2;

    var mx = msg2_buf[0..c.len];

    aegis.aegis256_state_init(&st, ad.ptr, ad.len, &nonce, &key);

    ret = aegis.aegis256_state_decrypt_detached_update(&st, mx.ptr, mx.len, &written, c0.ptr, c0.len);
    try testing.expectEqual(ret, 0);
    mx = mx[written..];

    ret = aegis.aegis256_state_decrypt_detached_update(&st, mx.ptr, mx.len, &written, c1.ptr, c1.len);
    try testing.expectEqual(ret, 0);
    mx = mx[written..];

    ret = aegis.aegis256_state_decrypt_detached_update(&st, mx.ptr, mx.len, &written, c2.ptr, c2.len);
    try testing.expectEqual(ret, 0);
    mx = mx[written..];

    ret = aegis.aegis256_state_decrypt_detached_final(&st, mx.ptr, mx.len, &written, &mac, mac.len);
    try testing.expectEqual(ret, 0);
    mx = mx[written..];

    try testing.expectEqual(mx.len, 0);
    try testing.expectEqualSlices(u8, msg, msg2_buf[0..msg.len]);
}

test "aegis-128x2 - test vector" {
    const key = [_]u8{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 };
    const nonce = [_]u8{ 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31 };
    const ad = [_]u8{ 1, 2, 3, 4 } ** 2;
    const msg = [_]u8{ 4, 5, 6, 7 } ** 30;
    var c = [_]u8{0} ** msg.len;
    var mac = [_]u8{0} ** 16;
    var mac256 = [_]u8{0} ** 32;
    var ret = aegis.aegis128x2_encrypt_detached(&c, &mac, mac.len, &msg, msg.len, &ad, ad.len, &nonce, &key);
    try testing.expectEqual(ret, 0);
    ret = aegis.aegis128x2_encrypt_detached(&c, &mac256, mac256.len, &msg, msg.len, &ad, ad.len, &nonce, &key);
    try testing.expectEqual(ret, 0);

    const expected_ciphertext_hex = "5795544301997f93621b278809d6331b3bfa6f18e90db12c4aa35965b5e98c5fc6fb4e54bcb6111842c20637252eff747cb3a8f85b37de80919a589fe0f24872bc926360696739e05520647e390989e1eb5fd42f99678a0276a498f8c454761c9d6aacb647ad56be62b29c22cd4b5761b38f43d5a5ee062f";
    try testing.expectEqualSlices(u8, &std.fmt.bytesToHex(c, .lower), expected_ciphertext_hex);

    const expected_tag_hex = "1aebc200804f405cab637f2adebb6d77";
    try testing.expectEqualSlices(u8, &std.fmt.bytesToHex(mac, .lower), expected_tag_hex);

    var msg2 = [_]u8{0} ** msg.len;
    ret = aegis.aegis128x2_decrypt_detached(&msg2, &c, c.len, &mac, mac.len, &ad, ad.len, &nonce, &key);
    try testing.expectEqual(ret, 0);
    try std.testing.expectEqualSlices(u8, &msg, &msg2);
}

test "aegis-128x2 - encrypt_detached oneshot" {
    try testing.expectEqual(aegis.aegis_init(), 0);

    inline for ([_]usize{ 16, 32 }) |mac_len| {
        var msg_buf: [max_msg_len]u8 = undefined;
        var msg2_buf: [msg_buf.len]u8 = undefined;
        var ad_buf: [max_ad_len]u8 = undefined;
        var c_buf: [msg_buf.len]u8 = undefined;
        var mac: [mac_len]u8 = undefined;

        random.bytes(&msg_buf);
        random.bytes(&ad_buf);

        for (0..iterations) |_| {
            const msg_len = random.intRangeAtMost(usize, 0, msg_buf.len);
            const msg = msg_buf[0..msg_len];
            var c = c_buf[0..msg_len];
            _ = &c;

            const ad_len = random.intRangeAtMost(usize, 0, ad_buf.len);
            const ad = &ad_buf[0..ad_len];

            var nonce: [aegis.aegis128x2_NPUBBYTES]u8 = undefined;
            random.bytes(&nonce);
            var key: [aegis.aegis128x2_KEYBYTES]u8 = undefined;
            random.bytes(&key);

            var ret = aegis.aegis128x2_encrypt_detached(c.ptr, &mac, mac_len, msg.ptr, msg.len, ad.ptr, ad.len, &nonce, &key);
            try testing.expectEqual(ret, 0);

            var msg2 = msg2_buf[0..msg_len];
            _ = &msg2;
            ret = aegis.aegis128x2_decrypt_detached(msg2.ptr, c.ptr, c.len, &mac, mac_len, ad.ptr, ad.len, &nonce, &key);
            try testing.expectEqual(ret, 0);
            try testing.expectEqualSlices(u8, msg, msg2);
        }
    }
}

test "aegis-128x4 - encrypt_detached oneshot" {
    try testing.expectEqual(aegis.aegis_init(), 0);

    inline for ([_]usize{ 16, 32 }) |mac_len| {
        var msg_buf: [max_msg_len]u8 = undefined;
        var msg2_buf: [msg_buf.len]u8 = undefined;
        var ad_buf: [max_ad_len]u8 = undefined;
        var c_buf: [msg_buf.len]u8 = undefined;
        var mac: [mac_len]u8 = undefined;

        random.bytes(&msg_buf);
        random.bytes(&ad_buf);

        for (0..iterations) |_| {
            const msg_len = random.intRangeAtMost(usize, 0, msg_buf.len);
            const msg = msg_buf[0..msg_len];
            const c = c_buf[0..msg_len];

            const ad_len = random.intRangeAtMost(usize, 0, ad_buf.len);
            const ad = &ad_buf[0..ad_len];

            var nonce: [aegis.aegis128x4_NPUBBYTES]u8 = undefined;
            random.bytes(&nonce);
            var key: [aegis.aegis128x4_KEYBYTES]u8 = undefined;
            random.bytes(&key);

            var ret = aegis.aegis128x4_encrypt_detached(c.ptr, &mac, mac_len, msg.ptr, msg.len, ad.ptr, ad.len, &nonce, &key);
            try testing.expectEqual(ret, 0);

            var msg2 = msg2_buf[0..msg_len];
            _ = &msg2;
            ret = aegis.aegis128x4_decrypt_detached(msg2.ptr, c.ptr, c.len, &mac, mac_len, ad.ptr, ad.len, &nonce, &key);
            try testing.expectEqual(ret, 0);
            try testing.expectEqualSlices(u8, msg, msg2);
        }
    }
}

test "aegis-128x4 - test vector" {
    const key = [_]u8{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 };
    const nonce = [_]u8{ 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31 };
    const ad = [_]u8{ 1, 2, 3, 4 } ** 2;
    const msg = [_]u8{ 4, 5, 6, 7 } ** 30;
    var c = [_]u8{0} ** msg.len;
    var mac = [_]u8{0} ** 16;
    var mac256 = [_]u8{0} ** 32;
    var ret = aegis.aegis128x4_encrypt_detached(&c, &mac, mac.len, &msg, msg.len, &ad, ad.len, &nonce, &key);
    try testing.expectEqual(ret, 0);
    ret = aegis.aegis128x4_encrypt_detached(&c, &mac256, mac256.len, &msg, msg.len, &ad, ad.len, &nonce, &key);
    try testing.expectEqual(ret, 0);

    const expected_ciphertext_hex = "e836118562f4479c9d35c17356a833114c21f9aa39e4dda5e5c87f4152a00fce9a7c38f832eafe8b1c12f8a7cf12a81a1ad8a9c24ba9dedfbdaa586ffea67ddc801ea97d9ab4a872f42d0e352e2713dacd609f9442c17517c5a29daf3e2a3fac4ff6b1380c4e46df7b086af6ce6bc1ed594b8dd64aed2a7e";
    try testing.expectEqualSlices(u8, &std.fmt.bytesToHex(c, .lower), expected_ciphertext_hex);

    const expected_tag_hex = "0e56ab94e2e85db80f9d54010caabfb4";
    try testing.expectEqualSlices(u8, &std.fmt.bytesToHex(mac, .lower), expected_tag_hex);

    var msg2 = [_]u8{0} ** msg.len;
    ret = aegis.aegis128x4_decrypt_detached(&msg2, &c, c.len, &mac, mac.len, &ad, ad.len, &nonce, &key);
    try testing.expectEqual(ret, 0);
    try std.testing.expectEqualSlices(u8, &msg, &msg2);
}

test "aegis-256x2 - test vector" {
    const key = [32]u8{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31 };
    const nonce = [32]u8{ 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47 };
    const ad = [_]u8{ 1, 2, 3, 4 } ** 2;
    const msg = [_]u8{ 5, 6, 7, 8 } ** 30;
    var c = [_]u8{0} ** msg.len;
    var mac = [_]u8{0} ** 16;
    var mac256 = [_]u8{0} ** 32;
    var ret = aegis.aegis256x2_encrypt_detached(&c, &mac, mac.len, &msg, msg.len, &ad, ad.len, &nonce, &key);
    try testing.expectEqual(ret, 0);
    ret = aegis.aegis256x2_encrypt_detached(&c, &mac256, mac256.len, &msg, msg.len, &ad, ad.len, &nonce, &key);
    try testing.expectEqual(ret, 0);

    const expected_ciphertext_hex = "73110d21a920608fd77b580f1e4428087a7365cb153b4eeca6b62e1a70f7f9a8d1f31f17da4c3acfacb2517f2f5e15758c35532e33751a964d18d29a599d2dc07f9378339b9d8c9fa03d30a4d7837cc8eb8b99bcbba2d11cd1a0f994af2b8f947ef18473bd519e5283736758480abc990e79d4ccab93dde9";
    try testing.expectEqualSlices(u8, &std.fmt.bytesToHex(c, .lower), expected_ciphertext_hex);

    const expected_tag_hex = "94a3bd44ad3381e36335014620ee638e";
    try testing.expectEqualSlices(u8, &std.fmt.bytesToHex(mac, .lower), expected_tag_hex);

    var msg2 = [_]u8{0} ** msg.len;
    ret = aegis.aegis256x2_decrypt_detached(&msg2, &c, c.len, &mac, mac.len, &ad, ad.len, &nonce, &key);
    try testing.expectEqual(ret, 0);
    try std.testing.expectEqualSlices(u8, &msg, &msg2);
}

test "aegis-256x4 - test vector" {
    const key = [32]u8{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31 };
    const nonce = [32]u8{ 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47 };
    const ad = [_]u8{ 1, 2, 3, 4 } ** 2;
    const msg = [_]u8{ 5, 6, 7, 8 } ** 30;
    var c = [_]u8{0} ** msg.len;
    var mac = [_]u8{0} ** 16;
    var mac256 = [_]u8{0} ** 32;
    var ret = aegis.aegis256x4_encrypt_detached(&c, &mac, mac.len, &msg, msg.len, &ad, ad.len, &nonce, &key);
    try testing.expectEqual(ret, 0);
    ret = aegis.aegis256x4_encrypt_detached(&c, &mac256, mac256.len, &msg, msg.len, &ad, ad.len, &nonce, &key);
    try testing.expectEqual(ret, 0);

    const expected_ciphertext_hex = "bec109547f8316d598b3b7d947ad4c0ef5b98e217cffa0d858ad49ae34109a95abc5b5fada820c4d6ae2fca0f5e2444e52a04a1edb7bec71408de3e19950052194506be3ba6a4de51a15a577ea0e4c14f7539a13e751a555f48d0f49fecffb220525e60d381e2efa803b09b7164ba59fdc66656affd51e06";
    try testing.expectEqualSlices(u8, &std.fmt.bytesToHex(c, .lower), expected_ciphertext_hex);

    const expected_tag_hex = "ec44b512d713f745547be345bcc66b6c";
    try testing.expectEqualSlices(u8, &std.fmt.bytesToHex(mac, .lower), expected_tag_hex);

    var msg2 = [_]u8{0} ** msg.len;
    ret = aegis.aegis256x4_decrypt_detached(&msg2, &c, c.len, &mac, mac.len, &ad, ad.len, &nonce, &key);
    try testing.expectEqual(ret, 0);
    try std.testing.expectEqualSlices(u8, &msg, &msg2);
}

test "aegis128l - Unauthenticated encryption" {
    const key = [16]u8{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 };
    const nonce = [16]u8{ 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31 };
    var msg: [100]u8 = undefined;
    var msg2: [100]u8 = undefined;

    random.bytes(&msg);
    aegis.aegis128l_encrypt_unauthenticated(&msg2, &msg, msg.len, &nonce, &key);
    try testing.expect(!std.mem.eql(u8, &msg, &msg2));
    aegis.aegis128l_decrypt_unauthenticated(&msg2, &msg2, msg2.len, &nonce, &key);
    try testing.expectEqualSlices(u8, &msg, &msg2);
}

test "aegis128l - Random stream" {
    const key = [16]u8{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 };
    var nonce = [16]u8{ 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31 };
    var msg: [100]u8 = undefined;
    var msg2: [100]u8 = undefined;
    aegis.aegis128l_stream(&msg, msg.len, &nonce, &key);
    aegis.aegis128l_stream(&msg2, msg2.len, &nonce, &key);
    try testing.expectEqualSlices(u8, &msg, &msg2);
    nonce[0] ^= 0x01;
    aegis.aegis128l_stream(&msg2, msg2.len, &nonce, &key);
    try testing.expect(!std.mem.eql(u8, &msg, &msg2));
}

test "aegis128l - MAC" {
    const key = [16]u8{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 };
    const msg = [_]u8{ 1, 2, 3 } ** 100;
    const msg2 = [_]u8{ 4, 5, 6, 7, 8 } ** 100;
    var st0: aegis.aegis128l_state = undefined;
    aegis.aegis128l_mac_init(&st0, &key);

    var st: aegis.aegis128l_state = undefined;
    aegis.aegis128l_mac_state_clone(&st, &st0);
    var ret = aegis.aegis128l_mac_update(&st, &msg, msg.len);
    try testing.expectEqual(ret, 0);
    ret = aegis.aegis128l_mac_update(&st, &msg2, msg2.len);
    try testing.expectEqual(ret, 0);
    var mac: [32]u8 = undefined;
    ret = aegis.aegis128l_mac_final(&st, &mac, mac.len);
    try testing.expectEqual(ret, 0);

    aegis.aegis128l_mac_state_clone(&st, &st0);
    ret = aegis.aegis128l_mac_update(&st, &msg, msg.len);
    try testing.expectEqual(ret, 0);
    ret = aegis.aegis128l_mac_update(&st, &msg2, msg2.len);
    try testing.expectEqual(ret, 0);
    ret = aegis.aegis128l_mac_verify(&st, &mac, mac.len);
    try testing.expectEqual(ret, 0);

    aegis.aegis128l_mac_state_clone(&st, &st0);
    const msg3 = msg ++ msg2;
    ret = aegis.aegis128l_mac_update(&st, &msg3, msg3.len);
    try testing.expectEqual(ret, 0);
    ret = aegis.aegis128l_mac_verify(&st, &mac, mac.len);
    try testing.expectEqual(ret, 0);

    const nonce = [_]u8{0} ** 16;
    var mac2: [mac.len]u8 = undefined;
    ret = aegis.aegis128l_encrypt_detached(&mac2, &mac2, mac2.len, "", 0, &msg3, msg3.len, &nonce, &key);
    try testing.expectEqual(ret, 0);
    try testing.expectEqualSlices(u8, &mac, &mac2);
}

test "aegis128x2 - MAC" {
    const key = [16]u8{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 };
    const msg = [_]u8{ 1, 2, 3 } ** 100;
    const msg2 = [_]u8{ 4, 5, 6, 7, 8 } ** 100;
    var st0: aegis.aegis128x2_state = undefined;
    aegis.aegis128x2_mac_init(&st0, &key);

    var st: aegis.aegis128x2_state = undefined;
    aegis.aegis128x2_mac_state_clone(&st, &st0);
    var ret = aegis.aegis128x2_mac_update(&st, &msg, msg.len);
    try testing.expectEqual(ret, 0);
    ret = aegis.aegis128x2_mac_update(&st, &msg2, msg2.len);
    try testing.expectEqual(ret, 0);
    var mac: [32]u8 = undefined;
    ret = aegis.aegis128x2_mac_final(&st, &mac, mac.len);
    try testing.expectEqual(ret, 0);

    aegis.aegis128x2_mac_state_clone(&st, &st0);
    ret = aegis.aegis128x2_mac_update(&st, &msg, msg.len);
    try testing.expectEqual(ret, 0);
    ret = aegis.aegis128x2_mac_update(&st, &msg2, msg2.len);
    try testing.expectEqual(ret, 0);
    ret = aegis.aegis128x2_mac_verify(&st, &mac, mac.len);
    try testing.expectEqual(ret, 0);

    aegis.aegis128x2_mac_state_clone(&st, &st0);
    const msg3 = msg ++ msg2;
    ret = aegis.aegis128x2_mac_update(&st, &msg3, msg3.len);
    try testing.expectEqual(ret, 0);
    ret = aegis.aegis128x2_mac_verify(&st, &mac, mac.len);
    try testing.expectEqual(ret, 0);

    const nonce = [_]u8{0} ** 16;
    var mac2: [mac.len]u8 = undefined;
    ret = aegis.aegis128x2_encrypt_detached(&mac2, &mac2, mac2.len, "", 0, &msg3, msg3.len, &nonce, &key);
    try testing.expectEqual(ret, 0);
    try testing.expectEqualSlices(u8, &mac, &mac2);
}

test "aegis128x4 - MAC" {
    const key = [16]u8{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 };
    const msg = [_]u8{ 1, 2, 3 } ** 100;
    const msg2 = [_]u8{ 4, 5, 6, 7, 8 } ** 100;
    var st0: aegis.aegis128x4_state = undefined;
    aegis.aegis128x4_mac_init(&st0, &key);

    var st: aegis.aegis128x4_state = undefined;
    aegis.aegis128x4_mac_state_clone(&st, &st0);
    var ret = aegis.aegis128x4_mac_update(&st, &msg, msg.len);
    try testing.expectEqual(ret, 0);
    ret = aegis.aegis128x4_mac_update(&st, &msg2, msg2.len);
    try testing.expectEqual(ret, 0);
    var mac: [32]u8 = undefined;
    ret = aegis.aegis128x4_mac_final(&st, &mac, mac.len);
    try testing.expectEqual(ret, 0);

    aegis.aegis128x4_mac_state_clone(&st, &st0);
    ret = aegis.aegis128x4_mac_update(&st, &msg, msg.len);
    try testing.expectEqual(ret, 0);
    ret = aegis.aegis128x4_mac_update(&st, &msg2, msg2.len);
    try testing.expectEqual(ret, 0);
    ret = aegis.aegis128x4_mac_verify(&st, &mac, mac.len);
    try testing.expectEqual(ret, 0);

    aegis.aegis128x4_mac_state_clone(&st, &st0);
    const msg3 = msg ++ msg2;
    ret = aegis.aegis128x4_mac_update(&st, &msg3, msg3.len);
    try testing.expectEqual(ret, 0);
    ret = aegis.aegis128x4_mac_verify(&st, &mac, mac.len);
    try testing.expectEqual(ret, 0);

    const nonce = [_]u8{0} ** 16;
    var mac2: [mac.len]u8 = undefined;
    ret = aegis.aegis128x4_encrypt_detached(&mac2, &mac2, mac2.len, "", 0, &msg3, msg3.len, &nonce, &key);
    try testing.expectEqual(ret, 0);
    try testing.expectEqualSlices(u8, &mac, &mac2);
}
