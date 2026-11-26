// Vendored copy of a public rule, not original work of this repository.
// Source: https://github.com/poonia80ravi/Yara_Rules/blob/ee330c25b1185e71476b192ac80b4dd2e11d25b5/windows/win.dilljuice_w0.yar
// Pinned: https://raw.githubusercontent.com/poonia80ravi/Yara_Rules/ee330c25b1185e71476b192ac80b4dd2e11d25b5/windows/win.dilljuice_w0.yar
// Author: poonia80ravi
// License: unspecified
// Fetched: 2026-11-26
// Techniques: header-arithmetic, pe-structure
// Expect: pass

import "pe"	

rule win_dilljuice_w0 {
    meta:
        author = "FireEye"
        source = "https://www.youtube.com/watch?v=a_CYCoL81bw"
        date = "2019-07-08"
        description = "Detection of DILLJUICE.A through its dropper"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.dilljuice"
        malpedia_version = "20190708"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:WHITE"
    condition:
        uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550 and 
        uint32(pe.rva_to_offset(0x177A0)) ^
        uint32(pe.rva_to_offset(0x177A0+8)) == 0x905A49

}
