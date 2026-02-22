import os
import re
import sys

# OpenVPN 源码在 ics-openvpn 中的路径
DIR = "main/src/main/cpp/openvpn/src/openvpn"

def update_file(filename, mod_func):
    path = os.path.join(DIR, filename)
    if not os.path.exists(path):
        print(f"❌ 致命错误: 找不到文件 {path}")
        sys.exit(1)
        
    with open(path, "r", encoding="utf-8") as f:
        content = f.read()
    
    orig_content = content
    # 执行修改函数
    content = mod_func(content)

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
        r'(int\s+connect_timeout;)',
        r'\1\n    int xormethod;\n    const char *xormask;\n    int xormasklen;',
        c, count=1
    )

update_file("options.h", mod_options_h)


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

update_file("options.c", mod_options_c)


# ================= 3. 终极无冲突解法: 集中修改 forward.c =================
def mod_forward_c(c):
    if "buffer_mask" not in c:
        xor_funcs = """
/* XOR Patch Helper Functions injected by script */
static void buffer_mask(struct buffer *buf, const char *mask, int xormasklen) {
    int i; uint8_t *b;
    if (xormasklen > 0) { for (i = 0, b = BPTR(buf); i < BLEN(buf); i++, b++) { *b = *b ^ mask[i % xormasklen]; } }
}
static void buffer_xorptrpos(struct buffer *buf) {
    int i; uint8_t *b;
    for (i = 0, b = BPTR(buf); i < BLEN(buf); i++, b++) { *b = *b ^ (i + 1); }
}
static void buffer_reverse(struct buffer *buf) {
    int len = BLEN(buf);
    if (len > 2) {
        int i; uint8_t *b_start = BPTR(buf) + 1; uint8_t *b_end = BPTR(buf) + (len - 1); uint8_t tmp;
        for (i = 0; i < (len - 1) / 2; i++, b_start++, b_end--) { tmp = *b_start; *b_start = *b_end; *b_end = tmp; }
    }
}
"""     
        # 1. 把混淆函数放在 forward.c 文件头部 include 的下方
        c = re.sub(r'(#include "syshead\.h")', r'\1\n' + xor_funcs, c, count=1)
        
        # 2. 收到包后的瞬间直接解密（正则匹配读取指令并紧跟解密逻辑）
        read_inject = """
    if (status > 0) {
        switch(c->options.ce.xormethod) {
            case 1: buffer_mask(&c->c2.buf, c->options.ce.xormask, c->options.ce.xormasklen); break;
            case 2: buffer_xorptrpos(&c->c2.buf); break;
            case 3: buffer_reverse(&c->c2.buf); break;
            case 4: buffer_mask(&c->c2.buf, c->options.ce.xormask, c->options.ce.xormasklen);
                    buffer_xorptrpos(&c->c2.buf);
                    buffer_reverse(&c->c2.buf);
                    buffer_xorptrpos(&c->c2.buf); break;
        }
    }
"""
        c = re.sub(
            r'(status\s*=\s*link_socket_read\s*\([^;]+;)', 
            r'\1\n' + read_inject, 
            c, count=1
        )
        
        # 3. 发送包前的瞬间直接加密（正则匹配发包指令并在前面安插加密逻辑）
        write_inject = """
                switch(c->options.ce.xormethod) {
                    case 1: buffer_mask(&c->c2.to_link, c->options.ce.xormask, c->options.ce.xormasklen); break;
                    case 2: buffer_xorptrpos(&c->c2.to_link); break;
                    case 3: buffer_reverse(&c->c2.to_link); break;
                    case 4: buffer_xorptrpos(&c->c2.to_link);
                            buffer_reverse(&c->c2.to_link);
                            buffer_xorptrpos(&c->c2.to_link);
                            buffer_mask(&c->c2.to_link, c->options.ce.xormask, c->options.ce.xormasklen); break;
                }
"""
        c = re.sub(
            r'(size\s*=\s*link_socket_write\s*\([^;]+;)',
            write_inject + r'                \1',
            c, count=1
        )
        
    return c

update_file("forward.c", mod_forward_c)

print("🎉 XOR 混淆结构已通过无冲突降维方案注入完毕！准备编译...")