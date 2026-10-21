// Vendored copy for study. Not original work of this repository.
// Source:   https://gist.github.com/notareverser/b14667284046f7fdcf8dd84e48add1bd
// Pinned:   https://gist.githubusercontent.com/notareverser/b14667284046f7fdcf8dd84e48add1bd/raw/ac5bda427bf3cb25b1d262824f28da4f74e58ff3/zlib.yara
// Author:   notareverser
// License:  unspecified (as declared by the source; see it for terms)
// Fetched:  2026-10-21

rule zlib
{
  strings:
      $distfix = {10 05 01 00 17 05 01 01 13 05 11 00 1b 05 01 10 11 05 05 00 19 05 01 04 15 05 41 00 1d 05 01 40 10 05 03 00 18 05 01 02 14 05 21 00 1c 05 01 20 12 05 09 00 1a 05 01 08 16 05 81 00 40 05 00 00 10 05 02 00 17 05 81 01 13 05 19 00 1b 05 01 18 11 05 07 00 19 05 01 06 15 05 61 00 1d 05 01 60 10 05 04 00 18 05 01 03 14 05 31 00 1c 05 01 30 12 05 0d 00 1a 05 01 0c 16 05 c1 00 40 05 00 00}

      $lenfix_prefix = {60 07 00 00 00 08 50 00 00 08 10 00 14 08 73 00 12 07 1f 00 00 08 70 00 00 08 30 00 00 09 c0 00 10 07 0a 00 00 08 60 00 00 08 20 00 00 09 a0 00 00 08 00 00 00 08 80 00 00 08 40 00 00 09 e0 00 10 07 06 00 00 08 58 00 00 08 18 00 00 09 90 00 13 07 3b 00 00 08 78 00 00 08 38 00 00 09 d0 00 11 07 11 00 00 08 68 00 00 08 28 00 00 09 b0 00 00 08 08 00 00 08 88 00 00 08 48 00 00 09 f0 00 10 07 04 00 00 08 54 00 00 08 14 00 15 08 e3 00 13 07 2b 00 00 08 74 00 }
  condition:
    all of them
}