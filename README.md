# FinalShell 密码解密工具（Python 版）

从 FinalShell 配置文件中解密保存的 SSH 密码。

## 依赖

```bash
pip install pycryptodome
```

## 使用方式

### 1. 自动检测本机 FinalShell（推荐）

双击脚本或无参数运行，自动从注册表检测安装路径并解密：

```
python finalshell解密.py
```

Windows 下会从注册表 `HKEY_CURRENT_USER\Software\finalshell` 读取安装目录，定位 `conn` 文件夹。

### 2. 拖放文件夹

将导出的 FinalShell 配置文件夹直接拖到 `.py` 脚本上即可解密。

### 3. 命令行指定目录

```
python finalshell解密.py -f <配置目录路径>
```

### 4. 解密单个加密密码

```
python finalshell解密.py <Base64加密密码>
```

### 5. 加密密码

```
python finalshell解密.py -e <明文密码>
```

## FinalShell 配置文件位置

| 系统 | 路径 |
|------|------|
| Windows | `%APPDATA%\finalshell\conn\` 或注册表 `HKCU\Software\finalshell` 下的安装目录 `\conn\` |
| macOS | `~/Library/FinalShell/conn/` |
| Linux | `~/.finalshell/conn/` |

配置文件格式为 `*_connect_config.json`，包含 `host`、`port`、`user_name`、`password` 等字段。

## 算法说明

1. Base64 解码密文，前 8 字节为 head，其余为 DES 密文
2. 用 `java.util.Random` 算法从 head 派生 DES 密钥（完整模拟 Java Random 种子计算和 nextLong 溢出回绕）
3. DES ECB 模式解密 + PKCS5 去填充
4. 得到明文密码

## 输出示例

```
名称                        主机                             端口       用户名                  解密密码
----------------------------------------------------------------------------------------------------
10.62.8.100               10.62.8.100                    22       epson                11119911
10.52.9.111               10.52.9.111                    22       root                 2222!!
```
