# Original USA disc + Title Update 4

The port is built from the **USA Rev 1** `default.xex` (see [inputs](inputs.md)).
The first USA pressing (media ID `26FF1101`, XEX `0.0.0.8`) runs the same
code once **Title Update 4** is applied: the patched executable has the
same size as the Rev 1 one, the same function addresses, the same data
addresses and the same protected-file table layout. `fm4tu` applies the
update the way the console does and writes a regular XEX2 file again.

## What you need

- Disc 1 of the original USA pressing, extracted to a folder (`default.xex`,
  `Media\`, ...). An ISO is not needed.
- Title Update 4: `26FF1101\tu00000008_00000000` (8,245,248 bytes,
  SHA-256 `bbc7c2317931b3cd74f2f321d9ad98ce6b63b894b5fc2d4a400957ce26654736`).
- Disc 2 and downloadable content are installed as usual. An extracted
  Disc 2 works through **Install → Additional content**: pick its
  `content\0000000000000000\4D530910\00000002` folder.

## Launcher

**Install → Step 1 (alternative) · Original USA disc + Title Update 4**: pick
the extracted Disc 1 folder, then the update package. The launcher copies the
folder into the game folder, runs `fm4tu apply` on the copy and then verifies
every file. The source folder is never modified.

Headless:

```
fm4-launcher --import-disc1-folder "D:\FM4\Disc 1" --title-update "D:\FM4\26FF1101\tu00000008_00000000" --game-dir game\disc1 --log install.log
```

Command line (development): `scripts\install_game.cmd --title-update "<Disc 1 folder>" "<tu00000008_00000000>"`.

## What `fm4tu apply <game_dir> <package>` does

1. Checks the package (SHA-256 above, title `4D530910`, media `26FF1101`,
   title-update content type) and the disc's `default.xex`,
   `SpeechFacade_default.xex` and `XMediaFacade_default.xex` against the
   original USA hashes.
2. Applies `disc001\default.xexp` (LZX delta, libmspack) to `default.xex`,
   rebuilds the encrypted XEX2 and requires SHA-256
   `10556f93213204deb7cec88a9f1c8b3aabce83a33760baa20ee4475f3c467930`.
   The original is kept as `.fm4-tu\default.xex.base`.
3. Extracts the update's Disc 1 files to `TitleUpdate\` and copies
   `Media\tracks\LeMans\patch_bin.zip` into the game folder, where the
   update's `tu_mount.xml` (and USA Rev 1) has it.
4. Checks the game's protected files against the SHA-256 table inside the
   patched executable (`0x82EA0000`); render scenarios are left to the
   launcher, which rewrites them for its graphics options.

On success it writes `.fm4-tu\prepared`, which tells the launcher to use
the adjusted manifest below. `fm4tu check <game_dir>` repeats the checks
without writing anything.

The facade modules stay the disc's own: USA Rev 1 ships them at the original
size, and the addresses in `config/speech.toml` and `config/xmedia.toml` match
them.

## Runtime

When `<game>\TitleUpdate\media.zip` exists, the game folder's `TitleUpdate`
is mounted read-only as `update:` before any guest code runs, as the console
does for an installed title update. The game then loads the update's
database patches, strings, textures and LeMans files from `update:\media.zip`.
USA Rev 1 has these merged into its own files and needs no `update:`.

## Verification

`launcher\data\game_files_usa_tu4.sha256` adjusts the Rev 1 manifest for
these installations (folders with `.fm4-tu\prepared`): 23 files
differ from Rev 1 (the executable, `hash.manifest`, string tables, `UI.zip`,
`gamedb.slt`, `zipmanifest.xml` and the two facades, whose headers carry the
other media ID) and three Rev 1 files are absent from the original disc
(`absent` lines; the update provides them). Every other file must be
identical to USA Rev 1.
