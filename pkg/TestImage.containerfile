FROM registry.opensuse.org/opensuse/leap:16.0

RUN zypper -n in vim-small; zypper -n clean

RUN mkdir -p /src/data/foo; echo "baz" > /src/data/foo/bar;

RUN rm /src/data/foo/bar

RUN rmdir /src/data/foo

# Opaque whiteout: create a directory with files, then replace its contents
# in a new layer. The builder should emit .wh..wh..opq to hide the old files.
RUN mkdir -p /opaque-test/dir && echo "old1" > /opaque-test/dir/file1 && echo "old2" > /opaque-test/dir/file2

RUN rm -rf /opaque-test/dir && mkdir -p /opaque-test/dir && echo "new" > /opaque-test/dir/newfile

# Nested directory whiteout: create a deep tree, then remove the top directory
# in a new layer. All children must disappear.
RUN mkdir -p /nested-test/a/b/c && echo "x" > /nested-test/a/b/c/file && echo "y" > /nested-test/a/top

RUN rm -rf /nested-test/a
