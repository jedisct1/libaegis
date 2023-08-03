const aegis = @cImport(@cInclude("aegis.h"));
const std = @import("std");
const random = std.crypto.random;
const testing = std.testing;

test "aegis-128l - encrypt_detached oneshot" {
    try testing.expectEqual(aegis.aegis_init(), 0);

    const mac_len: usize = 16;
    const max_msg_len: usize = 1000;
    const max_ad_len: usize = 1000;
    const iterations = 10000;

    var msg_buf: [max_msg_len]u8 = undefined;
    var msg2_buf: [msg_buf.len]u8 = undefined;
    var ad_buf: [max_ad_len]u8 = undefined;
    var c_buf: [msg_buf.len]u8 = undefined;
    var mac: [mac_len]u8 = undefined;

    random.bytes(&msg_buf);
    random.bytes(&ad_buf);

    for (0..iterations) |_| {
        const msg_len = random.intRangeAtMost(usize, 0, msg_buf.len);
        var msg = msg_buf[0..msg_len];
        var c = c_buf[0..msg_len];

        const ad_len = random.intRangeAtMost(usize, 0, ad_buf.len);
        const ad = &ad_buf[0..ad_len];

        var nonce: [aegis.aegis128l_NPUBBYTES]u8 = undefined;
        random.bytes(&nonce);
        var key: [aegis.aegis128l_KEYBYTES]u8 = undefined;
        random.bytes(&key);

        var ret = aegis.aegis128l_encrypt_detached(c.ptr, &mac, mac_len, msg.ptr, msg.len, ad.ptr, ad.len, &nonce, &key);
        try testing.expectEqual(ret, 0);

        var msg2 = msg2_buf[0..msg_len];
        ret = aegis.aegis128l_decrypt_detached(msg2.ptr, c.ptr, c.len, &mac, mac_len, ad.ptr, ad.len, &nonce, &key);
        try testing.expectEqual(ret, 0);
        try testing.expectEqualSlices(u8, msg, msg2);
    }
}
