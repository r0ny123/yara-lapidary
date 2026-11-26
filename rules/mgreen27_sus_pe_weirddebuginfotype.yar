// Vendored copy of a public rule, not original work of this repository.
// Source: https://github.com/mgreen27/100daysofyara/blob/9f414075d50016348e2c510ee2209300a9752487/2025/SUS_PE_WeirdDebugInfoType.yar
// Pinned: https://raw.githubusercontent.com/mgreen27/100daysofyara/9f414075d50016348e2c510ee2209300a9752487/2025/SUS_PE_WeirdDebugInfoType.yar
// Author: mgreen27
// License: unspecified
// Fetched: 2026-11-26
// Techniques: header-arithmetic, pe-structure
// Expect: pass

import "pe"

rule SUS_PE_WeirdDebugInfoType_Jan25
{
    meta:
        description = "Detects PE file with Debug directory not in the usual type - replicates Malcat WeirdDebugInfoType"
        author = "Matt Green - @mgreen27"
	reference = "https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_debug_directory"
        date = "2025-01-21"
    condition:
	uint16(0) == 0x5A4D
	and uint32(uint32(pe.rva_to_offset(pe.data_directories[pe.IMAGE_DIRECTORY_ENTRY_DEBUG].virtual_address) + 24)) == 0x53445352 //RSDS
	and not (
            uint32(pe.rva_to_offset(pe.data_directories[pe.IMAGE_DIRECTORY_ENTRY_DEBUG].virtual_address) + 12) == 2 or // IMAGE_DEBUG_TYPE_CODEVIEW
            uint32(pe.rva_to_offset(pe.data_directories[pe.IMAGE_DIRECTORY_ENTRY_DEBUG].virtual_address) + 12) == 13 or // IMAGE_DEBUG_TYPE_POGO
            uint32(pe.rva_to_offset(pe.data_directories[pe.IMAGE_DIRECTORY_ENTRY_DEBUG].virtual_address) + 12) == 16 or // IMAGE_DEBUG_TYPE_REPRO
            uint32(pe.rva_to_offset(pe.data_directories[pe.IMAGE_DIRECTORY_ENTRY_DEBUG].virtual_address) + 12) == 20 // IMAGE_DEBUG_TYPE_EX_DLLCHARACTERISTICS
        )
}
