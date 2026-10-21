// Vendored copy for study. Not original work of this repository.
// Source:   https://gist.github.com/notareverser/f1b0c4b871459af2adfe1d1e44c8fa1e
// Pinned:   https://gist.githubusercontent.com/notareverser/f1b0c4b871459af2adfe1d1e44c8fa1e/raw/eb54cf4b7f12bb42ded0519ca8fe4065310b3476/sevenzip_sfx.yara
// Author:   notareverser
// License:  unspecified (as declared by the source; see it for terms)
// Fetched:  2026-10-21

rule Windows_7z_SFX
{
  strings:
      $makeCommandFile_prefix_1 = {53 56 8b 75 08 66 83 7e 02 3a 0f 85 ?? ?? ?? ?? 0f b7 46 04 66 3d 5c 00 74 0a 66 3d 2f 00 0f 85 ?? ?? ?? ?? 66 8b 06 66 89 45 f0 8d 45 f0 33 db 50 66 c7 45 f2 3a 00 66 c7 45 f4 5c 00 66 89 5d f6 ff 15}

      $makeCommandFile_prefix_2 = {53 8b 45 08 33 db 89 5d fc 66 83 78 02 3a 0f 85 ?? ?? ?? ?? 66 8b 48 04 66 83 f9 5c 74 0a 66 83 f9 2f 0f 85 ?? ?? ?? ?? 66 8b 00 66 c7 45 e6 3a 00 66 89 45 e4 8d 45 e4 50 66 c7 45 e8 5c 00 66 89 5d ea ff 15}

      $makeCommandFile_prefix_3 = {53 56 8b 75 08 33 db 66 83 7e 02 3a 89 5d fc 0f 85 ?? ?? ?? ?? 66 8b 46 04 66 3d 5c 00 74 0a 66 3d 2f 00 0f 85 ?? ?? ?? ?? 66 8b 06 66 89 45 e4 8d 45 e4 50 66 c7 45 e6 3a 00 66 c7 45 e8 5c 00 66 89 5d ea ff 15}

      $makeCommandFile_prefix_4 = {8b 45 08 66 83 78 02 3a 0f 85 ?? ?? ?? ?? 0f b7 48 04 66 83 f9 5c 74 0a 66 83 f9 2f 0f 85 ?? ?? ?? ?? 66 8b 00 6a 3a 66 89 45 e8 58 66 89 45 ea 6a 5c 58 66 89 45 ec 33 c0 66 89 45 ee 8d 45 e8 50 ff 15}

      $makeCommandFile_prefix_5 = {66 83 78 02 3a 53 0f 85 ?? ?? ?? ?? 0f b7 48 04 66 83 f9 5c 74 0a 66 83 f9 2f 0f 85 ?? ?? ?? ?? 66 8b 00 6a 3a 66 89 45 f0 58 66 89 45 f2 6a 5c 58 66 89 45 f4 33 c0 66 89 45 f6 8d 45 f0 50 ff 15}

      $makeCommandFile_prefix_6 = {66 83 78 02 3a 53 0f 85 ?? ?? ?? ?? 0f b7 48 04 66 83 f9 5c 74 0a 66 83 f9 2f 0f 85 ?? ?? ?? ?? 66 8b 00 66 89 45 f0 8d 45 f0 33 db 50 66 c7 45 f2 3a 00 66 c7 45 f4 5c 00 66 89 5d f6 ff 15}

      $makeCommandFile_prefix_debug = {8b 84 24 88 00 00 00 66 83 78 02 3a 0f 85 ?? ?? ?? ?? 0f b7 48 04 66 83 f9 5c 74 0a 66 83 f9 2f 0f 85 ?? ?? ?? ?? 66 8b 08 ba 3a 00 00 00 66 89 54 24 2e 66 89 4c 24 2c 8d 54 24 2c b8 5c 00 00 00 33 c9 52 66 89 44 24 34 66 89 4c 24 36 ff 15}

      $makeCommandFile_prefix_x64 = {48 8b f9 48 8b 09 66 83 79 02 3a 0f 85 ?? ?? ?? ?? 66 83 79 04 5c 74 0b 66 83 79 04 2f 0f 85 ?? ?? ?? ?? 0f b7 01 66 83 a4 24 8e 00 00 00 00 48 8d 8c 24 88 00 00 00 66 89 84 24 88 00 00 00 66 c7 84 24 8a 00 00 00 3a 00 66 c7 84 24 8c 00 00 00 5c 00 ff 15}

      $command = "7ZSfx%03x.cmd" wide

  condition:
      1 of ($makeCommandFile*) and $command
}
