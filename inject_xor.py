import os
import re
import sys

# OpenVPN 源码在 ics-openvpn 中的路径
DIR = "main/src/main/cpp/openvpn/src/openvpn"

def update_file(filename, mod_func, check_keyword):
    path = os.path.join(DIR, filename)
    if not os.path.exists(path):
        print(f"❌ 致命错误: 找不到文件 {path}")
        sys.exit(1)
        
    with open(path, "r", encoding="utf-8") as f:
        content = f.read()
    
    if check_keyword in content:
        print(f"✅ {filename} 已经包含补丁，跳过二次注入。")
        return

    orig_content = content
    content = mod_func(content)

    if content == orig_content:
        print(f"❌ 致命错误: 无法给 {filename} 打补丁 (文件内容没有发生改变，可能是正则未匹配到目标代码)！")
        sys.exit(1)

    with open(path, "w", encoding="utf-8") as f:
        f.write(content)
    print(f"✅ 成功注入: {filename}")

# ================= 1. 修改 options.h =================
def mod_options_h(c):
    return re.sub(
        r'(int\s+connect_timeout;)',
        r'\1\n    int xormethod;\n    const char *xormask;\n    int xormasklen;',
        c, count=1
    )

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
    c = re.sub(r'(o->proto_force\s*=\s*-1;)', r'\1\n    o->ce.xormethod = 0;\n    o->ce.xormask = "\\0";\n    o->ce.xormasklen = 0;', c, count=1)
    # 取消了对 setenv 的注入，因为这是导致 NDK C 编译器报错的根源，且混淆特性根本不需要向环境变量暴露密码
    c = re.sub(r'(else if\s*\(\s*streq\s*\(\s*p\[0\],\s*"socks-proxy"\s*\)\s*\))', add_scramble.strip() + r'\n    \1', c, count=1)
    return c

# ================= 3. 修改 forward.c =================
def mod_forward_c(c):
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
    # 1. 极其安全的插入位置：寻找整个文件最后一个 #include，将辅助函数紧跟其后插入，确保所有依赖类型都已加载！
    last_inc = c.rfind('#include')
    end_of_inc = c.find('\n', last_inc)
    c = c[:end_of_inc] + "\n\n" + xor_funcs + c[end_of_inc:]
    
    # 2. 收到包后的瞬间解密 (移除对 status 变量的依赖，改用更安全的 buf.len 检查)
    read_inject = """
    if (c->c2.buf.len > 0) {
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
    c = re.sub(r'(status\s*=\s*link_socket_read\s*\([^;]+;)', r'\1\n' + read_inject, c, count=1)
    
    # 3. 发送包前的瞬间加密
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
    c = re.sub(r'(size\s*=\s*link_socket_write\s*\([^;]+;)', write_inject + r'                \1', c, count=1)
    
    return c

if __name__ == "__main__":
    update_file("options.h", mod_options_h, "int xormethod;")
    update_file("options.c", mod_options_c, "o->ce.xormethod = 0;")
    update_file("forward.c", mod_forward_c, "buffer_mask")
    print("🎉 XOR 混淆参数已全部安全、精准注入完毕！开始编译...")