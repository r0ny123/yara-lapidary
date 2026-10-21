// Vendored copy for study. Not original work of this repository.
// Source:   https://gist.github.com/notareverser/d892bc31423ad8ff8b68b9c78ec0ae6f
// Pinned:   https://gist.githubusercontent.com/notareverser/d892bc31423ad8ff8b68b9c78ec0ae6f/raw/5e31cfedec937e6ab85ac52b3ef228f376d6a298/innosetup.yara
// Author:   notareverser
// License:  unspecified (as declared by the source; see it for terms)
// Fetched:  2026-10-21

rule InnoSetup
{
   strings:
      $integrity_check_merged = {b9 ?? ?? ?? ?? b2 01 b8 ?? ?? ?? ?? e8 ?? ?? ?? ?? e8 ?? ?? ?? ?? c3 00 ff ff ff ff 47 00 00 00 54 68 65 20 73 65 74 75 70 20 66 69 6c 65 73 20 61 72 65 20 63 6f 72 72 75 70 74 65 64 2e 20 50 6c 65 61 73 65 20 6f 62 74 61 69 6e 20 61 20 6e 65 77 20 63 6f 70 79 20 6f 66 20 74 68 65 20 70 72 6f 67 72 61 6d 2e 00}
      $lzmadecompsmall = {53 83 c4 f8 8b d8 89 1c 24 c6 44 24 04 00 54 6a 00 b9 ?? ?? ?? ?? b2 01 b8 ?? ?? ?? ?? e8 ?? ?? ?? ?? e8 ?? ?? ?? ?? 59 5a 5b c3 00 ff ff ff ff 32 00 00 00 6c 7a 6d 61 64 65 63 6f 6d 70 73 6d 61 6c 6c 3a 20 43 6f 6d 70 72 65 73 73 65 64 20 64 61 74 61 20 69 73 20 63 6f 72 72 75 70 74 65 64 20 28 25 64 29 00}
      $lzma_merged = {53 83 c4 f8 8b d8 89 1c 24 c6 44 24 04 00 54 6a 00 b9 ?? ?? ?? ?? b2 01 ?? ?? ?? ?? ?? e8 ?? ?? ?? ?? e8 ?? ?? ?? ?? 59 5a 5b c3 00 ff ff ff ff 27 00 00 00 6c 7a 6d 61 3a 20 43 6f 6d 70 72 65 73 73 65 64 20 64 61 74 61 20 69 73 20 63 6f 72 72 75 70 74 65 64 20 28 25 64 29 00}
   condition:
      any of them
}
