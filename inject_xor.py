import os
import re

# OpenVPN 源码在 ics-openvpn 中的路径
DIR = "main/src/main/cpp/openvpn/src/openvpn"

def update_file(filename, modifications):
    path = os.path.join(DIR, filename)
    if not os.path.exists(path):
        print(f"File not found: {path}")
        return
        
    with open(path, "r", encoding="utf-8") as f:
        content = f.read()

    for mod in modifications:
        if callable(mod):
            content = mod(content)
        else:
            old, new = mod
            if old in content and new not in content:
                content = content.replace(old, new)

    with open(path, "w", encoding="utf-8") as f:
        f.write(content)
    print(f"✅ Patched {filename}")

# ================= 1. 修改 options.h =================
update_file("options.h", [
    ("int connect_timeout;", "int connect_timeout;\n    int xormethod;\n    const char *xormask;\n    int xormasklen;")
])

# ================= 2. 修改 options.c =================
add_scramble = """
    else if (streq(p[0], "scramble")) {
        VERIFY_PERMISSION(OPT_P_GENERAL|OPT_P_CONNECTION);
        if (p[1] && streq(p[1], "xormask") && p[2] && (!p[3])) {
            options->ce.xormethod = 1; options->ce.xormask = p[2]; options->ce.xormasklen = strlen(options->ce.xormask);
        } else if (p[1] && streq(p[1], "xorptrpos") && (!p[2])) {
            options->ce.xormethod = 2; options->ce.xormask = NULL; options->ce.xormasklen = 0;
        } else if (p[1] && streq(p[1], "reverse") && (!p[2])) {
            options->ce.xormethod = 3; options->ce.xormask = NULL; options->ce.xormasklen = 0;
        } else if (p[1] && streq(p[1], "obfuscate") && p[2] && (!p[3])) {
            options->ce.xormethod = 4; options->ce.xormask = p[2]; options->ce.xormasklen = strlen(options->ce.xormask);
        } else if (p[1] && (!p[2])) {
            msg(M_WARN, "WARNING: No recognized 'scramble' method specified; using 'scramble xormask \\"%s\\"'", p[1]);
            options->ce.xormethod = 1; options->ce.xormask = p[1]; options->ce.xormasklen = strlen(options->ce.xormask);
        } else {
            msg(msglevel, "No recognized 'scramble' method specified or extra parameters for 'scramble'");
            goto err;
        }
    }
    else if (streq(p[0], "socks-proxy"))"""

update_file("options.c", [
    ("o->proto_force = -1;", "o->proto_force = -1;\n    o->ce.xormethod = 0;\n    o->ce.xormask = \"\\0\";\n    o->ce.xormasklen = 0;"),
    ("setenv_str_i(es, \"remote_port\", e->remote_port, i);", "setenv_str_i(es, \"remote_port\", e->remote_port, i);\n    setenv_int_i(es, \"xormethod\", e->xormethod, i);\n    setenv_str_i(es, \"xormask\", e->xormask, i);\n    setenv_int_i(es, \"xormasklen\", e->xormasklen, i);"),
    ("else if (streq(p[0], \"socks-proxy\"))", add_scramble.strip())
])

# ================= 3. 修改 socket.c =================
socket_c_add = """
#include "socket.h"
int buffer_mask(struct buffer *buf, const char *mask, int xormasklen) {
    int i; uint8_t *b;
    if (xormasklen > 0) { for (i = 0, b = BPTR(buf); i < BLEN(buf); i++, b++) { *b = *b ^ mask[i % xormasklen]; } }
    return BLEN(buf);
}
int buffer_xorptrpos(struct buffer *buf) {
    int i; uint8_t *b;
    for (i = 0, b = BPTR(buf); i < BLEN(buf); i++, b++) { *b = *b ^ (i + 1); }
    return BLEN(buf);
}
int buffer_reverse(struct buffer *buf) {
    int len = BLEN(buf);
    if (len > 2) {
        int i; uint8_t *b_start = BPTR(buf) + 1; uint8_t *b_end = BPTR(buf) + (len - 1); uint8_t tmp;
        for (i = 0; i < (len - 1) / 2; i++, b_start++, b_end--) { tmp = *b_start; *b_start = *b_end; *b_end = tmp; }
    }
    return len;
}
"""
update_file("socket.c", [('#include "socket.h"', socket_c_add.strip())])

# ================= 4. 修改 socket.h =================
def mod_socket_h(c):
    # 暴露函数
    if "buffer_mask" not in c:
        c = c.replace("#include \"mtu.h\"", "int buffer_mask(struct buffer *buf, const char *xormask, int xormasklen);\nint buffer_xorptrpos(struct buffer *buf);\nint buffer_reverse(struct buffer *buf);\n#include \"mtu.h\"")
    # 拦截 Read
    c = re.sub(
        r'(static inline int\s+link_socket_read\(.*?struct link_socket_actual \*from)(\s*\)\s*\{.*?)(return res;\s*\})',
        r'\1, int xormethod, const char *xormask, int xormasklen\2\n    if (res > 0) {\n        buf->len = res;\n        switch(xormethod) {\n            case 1: buffer_mask(buf, xormask, xormasklen); break;\n            case 2: buffer_xorptrpos(buf); break;\n            case 3: buffer_reverse(buf); break;\n            case 4: buffer_mask(buf, xormask, xormasklen); buffer_xorptrpos(buf); buffer_reverse(buf); buffer_xorptrpos(buf); break;\n        }\n    }\n    \3',
        c, flags=re.DOTALL
    )
    # 拦截 Write
    c = re.sub(
        r'(static inline int\s+link_socket_write\(.*?struct link_socket_actual \*to)(\s*\)\s*\{)',
        r'\1, int xormethod, const char *xormask, int xormasklen\2\n    switch(xormethod) {\n        case 1: buffer_mask(buf, xormask, xormasklen); break;\n        case 2: buffer_xorptrpos(buf); break;\n        case 3: buffer_reverse(buf); break;\n        case 4: buffer_xorptrpos(buf); buffer_reverse(buf); buffer_xorptrpos(buf); buffer_mask(buf, xormask, xormasklen); break;\n    }\n',
        c, flags=re.DOTALL
    )
    return c

update_file("socket.h", [mod_socket_h])

# ================= 5. 修改 forward.c =================
def mod_forward_c(c):
    c = re.sub(r'(link_socket_read\(.*?\n.*?&c->c2\.from)(\s*\);)', r'\1, c->options.ce.xormethod, c->options.ce.xormask, c->options.ce.xormasklen\2', c, flags=re.DOTALL)
    c = re.sub(r'(link_socket_write\(.*?\n.*?to_addr)(\s*\);)', r'\1, c->options.ce.xormethod, c->options.ce.xormask, c->options.ce.xormasklen\2', c, flags=re.DOTALL)
    return c

update_file("forward.c", [mod_forward_c])
print("🎉 All XOR patches injected successfully!")
