# fnOS `.fot` 加密备份还原工具

[English](README.md)

`recover_fot.py` 用**备份时设置的密码**解密飞牛 fnOS 云备份中的 `.fot` 文件，恢复原始文件名，也能递归还原整个下载好的备份目录。

## 环境要求

- Python 3.9 或更新版本
- `cryptography`：`python3 -m pip install cryptography`

程序会在终端提示输入备份密码，不需要把密码写在命令行里。

## 用法

还原单个文件，自动使用原始文件名，保存在 `.fot` 旁边：

```sh
python3 recover_fot.py photo.fot
```

也可以明确指定输出文件名：

```sh
python3 recover_fot.py photo.fot restored-photo.jpg
```

还原整个目录，保存到另一个目录：

```sh
python3 recover_fot.py encrypted-folder restored-folder
```

目录模式只询问一次密码，保留下载后的目录结构，并只解密 `.fot` 文件；其他普通文件不会复制到输出目录。输出目录必须位于加密目录之外。已有文件不会被覆盖。
