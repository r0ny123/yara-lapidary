// Vendored copy for study. Not original work of this repository.
// Source:   https://gist.github.com/notareverser/d5f4f0d09285edca3ec027534c233271
// Pinned:   https://gist.githubusercontent.com/notareverser/d5f4f0d09285edca3ec027534c233271/raw/db140e7498b250f94ff6feca365704ab21b5ff37/YARA%20rules%20for%20%23100DaysOfYARA
// Author:   notareverser
// License:  unspecified (as declared by the source; see it for terms)
// Fetched:  2026-10-21

import "pe"

rule ASPack_PE
{
   strings:
      $unpackStub = {60 e8 03 00 00 00 e9 eb 04 5d 45 55 c3 e8 01 00 00 00 eb 5d bb ed ff ff ff}
   condition:
      $unpackStub at pe.entry_point or (uint8(@unpackStub-1) == 0x90)
}

rule PyInstaller_WellFormed
{
   strings:
      $magic = {4d 45 49 0c 0b 0a 0b 0e}
   condition:
      $magic in (filesize-96..filesize)
}

rule ARGS_OpenProcess_PROCESS_ALL_ACCESS
{
  strings:   
    $call_rel = {68 ff 0f 1f 00 e8 ?? ?? ?? ??}
    $call_abs = {68 ff 0f 1f 00 ff 15 ?? ?? ?? ??}
    $call_reg = {68 ff 0f 1f 00 ff d?}
  condition:
    any of them    
}

rule Golang
{
  strings:
     $header = {(fb | fa | f0) ff ff ff 00 00 ?? (04 | 08) }
     $val_buildid = "go.buildid"
     $val_init = "internal/cpu.Initialize"
     $val_cpuid = "internal/cpu.cpuid"
  condition:
     $header and any of ($val_*)
}

rule Delphi
{
 strings:
  $seh = {558bec[0-3]33c05568[4]64ff30648920}
  $init = {538bd833c0a3[4]6a00e8[4]a3[4]a1[4]a3[4]33c0a3[4]33c0a3[4]e8[4]ba[4]8bc3e8[4]5bc3}
 condition: any of them
}

rule LZO_Constants
{
   strings:
    // for humans
    //  firstKey = *buffer;
    //  if ( *buffer > 0x11u )
    $dindexConstant = {9d 42 24 18}
    $mov_0xc000 = {b? 00 c0 00 00}
   condition: all of them
}

rule ARGS_socket_TCPIP
{
  strings:
    $c_rel = {6a066a016a02e8????????}
    $c_abs = {6a066a016a02ff15????????}
    $c_reg = {6a066a016a02ffd?}
  condition:
    any of them
}

rule Shikata_ga_nai
{
   strings:
     $fn = {d97424f4}
     $pop_clr = {(58|5a|5b|5d|5e|5f)  (29|2b|31|33) c9}
     $pop_mov_clr = {(58|5a|5b|5d|5e|5f) b?[4] (29|2b|31|33) c9}
   condition:
   
     for any of ($pop_*) : (((@ - @fn)==4) or ((@ - @fn)==9))
}

rule AutoITv3_UPX
{
   strings:
      $ = {6edffeffb9000c3144e81103a2bd680003a55912021d3c59c320003970269593546338ae69937427e9396e2c92217316a97c279545785122e76b7df2757f3ba1ee43}
   condition:
      1 of them
}

rule WinRAR_SFX
{
   strings:
      $chk = {80 7? 01 61 75 ?? 80 7? 02 72 75 ?? 80 7? 03 21 75 ?? 80 7? 04 1a 75 ?? 80 7? 05 07 75}
      $mag = {52 61 72 21 1a 07}
   condition:
      all of them
}

rule CallOverString
{
  strings:
    $imp_1 = "LoadLibraryA"
    $imp_2 = "WinHttpOpen"

  condition:

    for any of ($imp_*) : ( (uint8(@ - 5) == 0xe8) and (uint32(@ -4) == !) and (uint8(@ + !) & 0x50) == 0x50) 
}

rule VB
{
    strings:
      $m = "VB5!"
    condition:
      $m and uint8(pe.entry_point) == 0x68 and uint8(pe.entry_point+5) == 0xe8 and (@m == (pe.rva_to_offset(uint32(pe.entry_point + 1) - pe.image_base)))
}

rule ARGS_WSAStartup_VersionRequested_0x202
{
  strings:
    // umm, why does {68 02 02 00 00 e8 [4]} produce a syntax error?
    $call_rel = {68 02 02 00 00 e8 ?? ?? ?? ??}
    $call_abs = {68 02 02 00 00 ff 15 ?? ?? ?? ??}
    $call_reg = {68 02 02 00 00 ff d?}
  condition:
    any of them
}

rule OverlayMZ
{
  strings:
    $mz = {4d 5a}
  condition:
    for any i in (1..#mz) : ( pe.overlay.offset != 0 and @mz[i] >= pe.overlay.offset )
}
