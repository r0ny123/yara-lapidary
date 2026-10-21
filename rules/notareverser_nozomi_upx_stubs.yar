// Vendored copy for study. Not original work of this repository.
// Source:   https://gist.github.com/notareverser/6c9b3f8cff0730bd0b9d19bacce4d5be
// Pinned:   https://gist.githubusercontent.com/notareverser/6c9b3f8cff0730bd0b9d19bacce4d5be/raw/b7cf5e76627efd7225f64bbc67602525600c1921/nozomi_upx.yara
// Author:   notareverser
// License:  unspecified (as declared by the source; see it for terms)
// Fetched:  2026-10-21

// https://github.com/NozomiNetworks/upx-recovery-tool
rule UPX_nozomi_x86
{
  strings: $sig = { 50 e8 ?? ?? 00 00 eb  5a 58 59 97 60 8a 54 24 20 e9 ?? ?? 00 00 60 8b 74 24 24 8b 7c 24 2c 83 cd}
  condition: any of them
}

rule UPX_nozomi_x64
{
  strings:
    $sig_ucl = {50 52 e8 ?? ?? ?? ?? 55 53 51 52 48 01 fe 56 48 89 fe 48 89 d7 31 db 31 c9 48 83 cd ff e8}
    $sig_lzma = { 50 52 e8 ?? ?? ?? ?? 55 53 51 52 48 01 fe 56 41 80 f8 0e 0f ?? ?? ?? ?? ?? 55 48 89 e5 44 8b 09}
  condition: any of them
}

rule UPX_nozomi_MIPS_be
{
  strings:
    $sig_1 = {04 11 ?? ?? 27 fe 00 00 27 bd ff fc af bf 00 00 00 a4 28 20 ac e6 00 00 3c 0d 80 00 01 a0 48 21 24 0b 00 01 04 11}
    $sig_2 = { 04 11 ?? ?? 27 f7 00 00 90 99 00 00 24 01 fa 00 90 98 00 01 33 22 00 07 00 19 c8 c2 03 21 08 04}
  condition: any of them
}

rule UPX_nozomi_MIPS_le
{
  strings: 
    $sig_1 = { 11 04 00 00 fe 27 fc ff bd 27 00 00 bf af 20 28 a4 00 00 00 e6 ac 00 80 0d 3c 21 48 a0 01 01 00 0b 24 ?? ?? 11 04}
    $sig_2 = { 11 04 00 00 f7 27 00 00 99 90 00 fa 01 24 01 00 98 90 07 00 22 33 c2 c8 19 00 04 08 21 03}
  condition: any of them
}

rule UPX_nozomi_ARM
{
  strings:
    $val1 = { 1c c0 4f e2 ?? ?? 9c e8 02 00 a0 e1 0c b0 8b e0 0c a0 8a e0 00 30 9b e5 01 90 4c e0 01 20 a0 e1}
    $val2 = { 18 d0 4d e2 ?? ?? 00 eb 00 c0 dd e5 0e 00 5c e3  02 00 1a 0c 48 2d e9 00 b0 d0 e5 06 cc a0 e3}
    $val3 = { 18 d0 4d e2 ?? ?? 00 eb 00 10 81 e0 3e 40 2d e9 00 50 e0 e3 02 41 a0 e3 ?? ?? 00 ea 1a 00 bd e8}
  condition: any of them
}

rule UPX_nozomi_PPC_cisco_4500
{
  strings:
    $ucl = { 48 00 ?? ?? 7c 00 29 ec 7d a8 02 a6 28 07 00 02 40 82 00 e4 90 a6 00 00}
    $lzma = { 48 00 ?? ?? 28 07 00 0e 40 82 0a 4c 94 21 ff e8 7c 08 02 a6 7c c9 33 78 81 06 00 00 7c a7 2b 78}
  condition: any of them
}
