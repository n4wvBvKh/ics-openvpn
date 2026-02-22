import os
import re
import sys

# OpenVPN 源码在 ics-openvpn 中的路径
DIR = "main/src/main/cpp/openvpn/src/openvpn"

def update_file(filename, modifications):
    path = os.path.join(DIR, filename)
    if not os.path.exists(path):
        print(f"❌ 致命错误: 找不到文件 {path}")
        sys.exit(1)
        
    with open(path, "r", encoding="utf-8") as f:
        content = f.read()
    orig_content = content

    # 逐一应用修改
    for mod in modifications:
        content = mod(content)

    # 严格校验：如果内容毫无变化，说明正则失效了，立即熔断！
    if content == orig_content:
        print(f"❌ 致命错误: 无法给 {filename} 打补丁 (文件内容没有发生改变，可能是正则未匹配到目标代码)！")
        sys.exit(1)

    with open(path, "w", encoding="utf-8") as f:
        f.write(content)
    print(f"✅ 成功注入: {filename}")

# ================= 1. 修改 options.h =================
def mod_options_h(c):
    if "int xormethod;" in c: return c
    return re.sub(
        r'(int connect_timeout;)',
        r'\1\n    int xormethod;\n    const char *xormask;\n    int xormasklen;',
        c, count=1
    )

update_file("options.h", [mod_options_h])

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
    }"""

def mod_options_c(c):
    if "xormethod =" not in c:
        c = re.sub(r'(o->proto_force\s*=\s*-1;)', r'\1\n    o->ce.xormethod = 0;\n    o->ce.xormask = "\\0";\n    o->ce.xormasklen = 0;', c, count=1)
        c = re.sub(r'(setenv_str_i\s*\(\s*es,\s*"remote_port".*?;)', r'\1\n    setenv_int_i(es, "xormethod", e->xormethod, i);\n    setenv_str_i(es, "xormask", e->xormask, i);\n    setenv_int_i(es, "xormasklen", e->xormasklen, i);', c, count=1)
        c = re.sub(r'(else if\s*\(\s*streq\s*\(\s*p\[0\],\s*"socks-proxy"\s*\)\s*\))', add_scramble.strip() + r'\n    \1', c, count=1)
    return c

update_file("options.c", [mod_options_c])

# ================= 3. 修改 socket.c =================
socket_c_add = """
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
def mod_socket_c(c):
    if "buffer_mask" not in c:
        c = c.replace('#include "socket.h"', '#include "socket.h"\n' + socket_c_add)
    return c

update_file("socket.c", [mod_socket_c])

# ================= 4. 修改 socket.h =================
def mod_socket_h(c):
    if "buffer_mask" not in c:
        c = c.replace('#include "mtu.h"', 'int buffer_mask(struct buffer *buf, const char *xormask, int xormasklen);\nint buffer_xorptrpos(struct buffer *buf);\nint buffer_reverse(struct buffer *buf);\n#include "mtu.h"')

    # 拦截 Read
    if "int xormethod" not in c:
        match_read = re.search(r'(static inline int\s+link_socket_read\(.*?struct link_socket_actual \*from)(\s*\)\s*\{)(.*?)(^\})', c, re.DOTALL | re.MULTILINE)
        if match_read:
            sig, brace, body, end = match_read.groups()
            new_sig = sig + ", int xormethod, const char *xormask, int xormasklen"
            # 将直接的 return 提取为 res 变量，以支持后缀处理
            new_body = "    int res;\n" + re.sub(r'return\s+(sock->read_func.*?;)', r'res = \1', body)
            new_body += """
    if (res > 0) {
        buf->len = res;
        switch(xormethod) {
            case 1: buffer_mask(buf, xormask, xormasklen); break;
            case 2: buffer_xorptrpos(buf); break;
            case 3: buffer_reverse(buf); break;
            case 4: buffer_mask(buf, xormask, xormasklen); buffer_xorptrpos(buf); buffer_reverse(buf); buffer_xorptrpos(buf); break;
        }
    }
    return res;
"""
            c = c[:match_read.start()] + new_sig + brace + new_body + end + c[match_read.end():]
        else:
            print("❌ 致命错误: socket.h 的 link_socket_read 正则匹配失败！")
            sys.exit(1)

        # 拦截 Write
        match_write = re.search(r'(static inline int\s+link_socket_write\(.*?struct link_socket_actual \*to)(\s*\)\s*\{)', c, re.DOTALL | re.MULTILINE)
        if match_write:
            sig, brace = match_write.groups()
            new_sig = sig + ", int xormethod, const char *xormask, int xormasklen"
            insertion = """
    switch(xormethod) {
        case 1: buffer_mask(buf, xormask, xormasklen); break;
        case 2: buffer_xorptrpos(buf); break;
        case 3: buffer_reverse(buf); break;
        case 4: buffer_xorptrpos(buf); buffer_reverse(buf); buffer_xorptrpos(buf); buffer_mask(buf, xormask, xormasklen); break;
    }
"""
            c = c[:match_write.start()] + new_sig + brace + insertion + c[match_write.end():]
        else:
            print("❌ 致命错误: socket.h 的 link_socket_write 正则匹配失败！")
            sys.exit(1)

    return c

update_file("socket.h", [mod_socket_h])

# ================= 5. 修改 forward.c =================
def mod_forward_c(c):
    if "c->options.ce.xormethod" not in c:
        # 修改 Read
        c_new = re.sub(
            r'(link_socket_read\s*\(\s*c->c2\.link_socket,\s*&c->c2\.buf,\s*&c->c2\.from)(\s*\))',
            r'\1, c->options.ce.xormethod, c->options.ce.xormask, c->options.ce.xormasklen\2',
            c, count=1
        )
        if c_new == c:
            print("❌ 致命错误: forward.c 的 read 匹配失败！")
            sys.exit(1)
        c = c_new
        
        # 修改 Write
        c_new = re.sub(
            r'(link_socket_write\s*\(\s*c->c2\.link_socket,\s*&c->c2\.to_link,\s*to_addr)(\s*\))',
            r'\1, c->options.ce.xormethod, c->options.ce.xormask, c->options.ce.xormasklen\2',
            c, count=1
        )
        if c_new == c:
            print("❌ 致命错误: forward.c 的 write 匹配失败！")
            sys.exit(1)
        c = c_new
    return c

update_file("forward.c", [mod_forward_c])

print("🎉 XOR 混淆参数已全部安全、精准注入完毕！开始编译...")