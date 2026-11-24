# libmspack (LZX decoder only)

Unmodified `lzxd.c` and the headers it needs from
[libmspack](https://github.com/kyz/libmspack), commit
`8f2a2a91ae2d12f985a196d481962ca4731f0f4d`. Licensed under the GNU LGPL 2.1
(`COPYING.LIB`).

`tools/fm4tu` uses it to decode the LZX delta blocks of an Xbox 360 title
update (`default.xexp`), the same way Xenia does.
