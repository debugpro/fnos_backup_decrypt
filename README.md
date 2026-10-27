# fnOS `.fot` backup recovery

[简体中文](README.zh-CN.md)

`recover_fot.py` restores files from password-encrypted fnOS cloud backups. It uses the **backup password** to decrypt `.fot` files, recovers their original filenames, and can process a downloaded backup folder recursively.

## Requirements

- Python 3.9 or newer
- `cryptography` (`python3 -m pip install cryptography`)

The password is requested interactively and is not passed on the command line.

## Usage

Restore one file beside the `.fot`, using its original filename:

```sh
python3 recover_fot.py photo.fot
```

To choose an exact output filename, add it as the second argument:

```sh
python3 recover_fot.py photo.fot restored-photo.jpg
```

Restore a whole folder into a separate output folder:

```sh
python3 recover_fot.py encrypted-folder restored-folder
```

Folder recovery asks for the password once, preserves the downloaded directory structure, and only decrypts `.fot` files. Other files are not copied. The output folder must be outside the encrypted folder. Existing outputs are never overwritten.
