"""
FinalShell 密码解密工具 - Python 版
翻译自 FinalShellDecodePass.java

用法:
  python finalshell_decoder.py                  自动检测本机 FinalShell 并解密
  python finalshell_decoder.py <加密密码>        解密单个密码
  python finalshell_decoder.py -f <目录路径>     扫描指定目录解密所有密码
  python finalshell_decoder.py -e <明文密码>     加密密码

拖放支持:
  将导出的 FinalShell 配置文件夹直接拖到脚本上即可解密

Windows 自动检测:
  从注册表 HKEY_CURRENT_USER\Software\finalshell 读取安装路径
"""

import base64
import hashlib
import io
import json
import os
import struct
import sys
from pathlib import Path

if sys.platform == 'win32':
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace')

MULTIPLIER = 0x5DEECE66D
ADDEND = 0xB
MASK = (1 << 48) - 1


class JavaRandom:
    """精确模拟 java.util.Random (JDK 8+)"""

    def __init__(self, seed):
        # Java: this.seed = (seed ^ multiplier) & mask
        # seed 是 long，需要处理负数
        if seed < 0:
            seed = seed + (1 << 64)
        self._seed = (seed ^ MULTIPLIER) & MASK

    def _next(self, bits):
        self._seed = (self._seed * MULTIPLIER + ADDEND) & MASK
        # Java: (int)(nextseed >>> (48 - bits))
        # >>> 无符号右移，(int) 截断为 signed 32-bit
        result = self._seed >> (48 - bits)
        if bits >= 32 and result >= 0x80000000:
            result -= 0x100000000
        return result

    def next_int(self, bound=None):
        if bound is None:
            return self._next(32)
        if bound <= 0:
            raise ValueError("bound must be positive")
        r = self._next(31)
        m = bound - 1
        if (bound & m) == 0:  # bound 是 2 的幂
            r = (bound * r) >> 31
        else:
            u = r
            r = u % bound
            while u - r + m < 0:
                u = self._next(31)
                r = u % bound
        return r

    def next_long(self):
        # Java: ((long)(next(32)) << 32) + (long)(next(32))
        # next(32) 返回 int（signed），(long) 是符号扩展
        hi = self._next(32)  # signed int
        lo = self._next(32)  # signed int
        # Java long 溢出回绕
        val = (hi << 32) + lo
        val = val & 0xFFFFFFFFFFFFFFFF
        if val >= 0x8000000000000000:
            val -= 0x10000000000000000
        return val


def ran_dom_key(head: bytes) -> bytes:
    """根据头部8字节生成DES密钥，精确翻译 Java ranDomKey"""
    def to_signed_byte(b):
        return b - 256 if b >= 128 else b

    # long ks = 3680984568597093857L / (long)(new Random((long)head[5])).nextInt(127);
    head5 = to_signed_byte(head[5])
    rand_for_divisor = JavaRandom(head5)
    divisor = rand_for_divisor.next_int(127)
    if divisor == 0:
        divisor = 1
    ks = 3680984568597093857 // divisor

    # Random random = new Random(ks);
    # int t = head[0];
    random = JavaRandom(ks)
    t = to_signed_byte(head[0])

    # for(int i = 0; i < t; ++i) { random.nextLong(); }
    if t > 0:
        for _ in range(t):
            random.next_long()

    # long n = random.nextLong();
    n = random.next_long()

    # Random r2 = new Random(n);
    r2 = JavaRandom(n)

    # long[] ld = {(long)head[4], r2.nextLong(), (long)head[7], (long)head[3], r2.nextLong(), (long)head[1], random.nextLong(), (long)head[2]};
    ld = [
        to_signed_byte(head[4]),
        r2.next_long(),
        to_signed_byte(head[7]),
        to_signed_byte(head[3]),
        r2.next_long(),
        to_signed_byte(head[1]),
        random.next_long(),
        to_signed_byte(head[2]),
    ]

    # DataOutputStream.writeLong — 大端序8字节
    key_data = b''
    for l in ld:
        key_data += struct.pack('>q', l)

    # MD5
    key_data = hashlib.md5(key_data).digest()
    return key_data


def des_decode(data: bytes, key: bytes) -> bytes:
    """DES ECB 解密"""
    from Crypto.Cipher import DES as CryptoDES
    cipher = CryptoDES.new(key[:8], CryptoDES.MODE_ECB)
    decrypted = cipher.decrypt(data)
    # Java DES 默认 PKCS5Padding
    pad_len = decrypted[-1]
    if 1 <= pad_len <= 8 and all(b == pad_len for b in decrypted[-pad_len:]):
        decrypted = decrypted[:-pad_len]
    return decrypted


def des_encode(data: bytes, head: bytes) -> bytes:
    """DES ECB 加密"""
    from Crypto.Cipher import DES as CryptoDES
    key = ran_dom_key(head)
    pad_len = 8 - (len(data) % 8)
    data = data + bytes([pad_len] * pad_len)
    cipher = CryptoDES.new(key[:8], CryptoDES.MODE_ECB)
    return cipher.encrypt(data)


def decode_pass(data: str) -> str:
    """解密 FinalShell 密码"""
    if not data:
        return ''
    data = data.strip()
    if not data:
        return ''
    buf = base64.b64decode(data)
    head = buf[:8]
    d = buf[8:]
    key = ran_dom_key(head)
    bt = des_decode(d, key)
    return bt.decode('utf-8', errors='replace')


def encode_pass(plaintext: str) -> str:
    """加密 FinalShell 密码"""
    if not plaintext:
        return ''
    import random as _random
    head = bytes([JavaRandom(_random.randint(0, 2**48)).next_int(127) & 0xFF for _ in range(8)])
    d = des_encode(plaintext.encode('utf-8'), head)
    result = head + d
    return base64.b64encode(result).decode('utf-8').replace('\n', '')


def get_finalshell_conn_dir() -> str:
    """自动检测 FinalShell 安装位置，返回 conn 目录路径"""
    # 1. Windows: 从注册表读取安装路径
    if sys.platform == 'win32':
        try:
            import winreg
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, r'Software\finalshell')
            install_dir, _ = winreg.QueryValueEx(key, '')
            winreg.CloseKey(key)
            if install_dir:
                conn_dir = os.path.join(install_dir, 'conn')
                if os.path.isdir(conn_dir):
                    return conn_dir
        except (OSError, FileNotFoundError):
            pass

        # 2. Windows 默认路径
        default_conn = os.path.join(os.environ.get('APPDATA', ''), 'finalshell', 'conn')
        if os.path.isdir(default_conn):
            return default_conn

    # 3. macOS
    mac_conn = os.path.expanduser('~/Library/FinalShell/conn')
    if os.path.isdir(mac_conn):
        return mac_conn

    # 4. Linux
    linux_conn = os.path.expanduser('~/.finalshell/conn')
    if os.path.isdir(linux_conn):
        return linux_conn

    return None


def scan_config_dir(config_dir: str):
    """扫描 FinalShell 配置目录，解密所有密码"""
    config_path = Path(config_dir)
    if not config_path.exists():
        print(f"目录不存在: {config_dir}")
        return

    json_files = list(config_path.glob("**/*_connect_config.json"))
    if not json_files:
        json_files = list(config_path.glob("**/*.json"))
    if not json_files:
        print(f"未找到配置文件: {config_dir}")
        return

    results = []
    for jf in sorted(json_files):
        try:
            with open(jf, 'r', encoding='utf-8') as f:
                content = json.load(f)
            name = content.get('name', content.get('#name', '未知'))
            host = content.get('host', content.get('#host', ''))
            port = content.get('port', content.get('#port', 22))
            user = content.get('user_name', content.get('user', ''))
            enc_pwd = content.get('password', content.get('#password', ''))
            dec_pwd = ''
            if enc_pwd:
                try:
                    dec_pwd = decode_pass(enc_pwd)
                except Exception as e:
                    dec_pwd = f'[解密失败: {e}]'
            results.append({
                'name': name, 'host': host, 'port': port,
                'user': user, 'password_dec': dec_pwd,
            })
        except Exception as e:
            print(f"解析文件失败 {jf}: {e}")

    if not results:
        print("未找到有效的连接配置")
        return

    print(f"{'名称':<25} {'主机':<30} {'端口':<8} {'用户名':<20} {'解密密码'}")
    print("-" * 100)
    for r in results:
        print(f"{r['name']:<25} {r['host']:<30} {r['port']:<8} {r['user']:<20} {r['password_dec']}")
    return results


def main():
    args = sys.argv[1:]

    # 无参数：自动检测本机 FinalShell
    if not args:
        print("FinalShell 密码解密工具 - Python 版\n")
        conn_dir = get_finalshell_conn_dir()
        if conn_dir:
            print(f"检测到 FinalShell 配置目录: {conn_dir}\n")
            scan_config_dir(conn_dir)
        else:
            print("未检测到本机 FinalShell 安装！")
            print("\n请使用以下方式指定配置目录:")
            print(f"  python {sys.argv[0]} -f <配置目录路径>")
            print("\n或将导出的 FinalShell 配置文件夹拖放到本脚本上")
        input("\n按回车键退出...")
        return

    # -f 参数：扫描指定目录
    if args[0] == '-f':
        if len(args) < 2:
            print("请指定配置目录路径")
            return
        scan_config_dir(args[1])
        input("\n按回车键退出...")
        return

    # -e 参数：加密密码
    if args[0] == '-e':
        if len(args) < 2:
            print("请指定要加密的密码")
            return
        enc = encode_pass(args[1])
        print(f"加密结果: {enc}")
        return

    # 第一个参数是目录路径（拖放文件夹场景）：检测是否为目录
    target = args[0]
    if os.path.isdir(target):
        print(f"扫描目录: {target}\n")
        scan_config_dir(target)
        input("\n按回车键退出...")
        return

    # 否则当作加密密码解密
    enc_pwd = target
    try:
        dec_pwd = decode_pass(enc_pwd)
        print(f"解密结果: {dec_pwd}")
    except Exception as e:
        print(f"解密失败: {e}")


if __name__ == '__main__':
    main()
