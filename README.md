<div align="center">
  <img src="skiff-logo.svg" width="35%" alt="skiff">
</div>

# skiff - OCI image analysis utility

A simple OCI image analysis utility, helping you uncover what consumes so much disk space in your container images.

## Installation

### From Source
```bash
git clone https://github.com/dcermak/skiff
cd skiff
make binaries
```

## Usage

### `skiff layers`

Print the size of each layer in an image.

**Usage:**
```bash
$ skiff layers registry.suse.com/bci/python@sha256:677b52cc1d587ff72430f1b607343a3d1f88b15a9bbd999601554ff303d6774f
Diff ID       Uncompressed Size
4672d0cba723  125604864
88304527ded0  129486336
```

### `skiff top`

Analyze a container image and list files by size (top 10 largest files).

```
$ skiff top registry.suse.com/bci/python@sha256:677b52cc1d587ff72430f1b607343a3d1f88b15a9bbd999601554ff303d6774f
FILE PATH                          SIZE     DIFF ID
/usr/bin/container-suseconnect     9245304  4672d0cba723
/usr/lib64/libzypp.so.1735.1.1     8767504  4672d0cba723
/usr/lib/sysimage/rpm/Packages.db  7837536  88304527ded0
/usr/lib64/libpython3.11.so.1.0    5876440  88304527ded0
/usr/lib64/libcrypto.so.3.1.4      5715672  4672d0cba723
/usr/lib/sysimage/rpm/Packages.db  5190128  4672d0cba723
/usr/share/misc/magic.mgc          4983184  4672d0cba723
/usr/lib/git/git                   3726520  88304527ded0
/usr/lib/locale/locale-archive     3058640  4672d0cba723
/usr/bin/zypper                    2915456  4672d0cba723
```

## Use Cases

- Image Optimization - Identify large files and unnecessary layers to reduce image size
- Layer Debugging - Understand what each layer contributes to the final image

## Contributing

Contributions are welcome! Please feel free to submit issues and pull requests.
