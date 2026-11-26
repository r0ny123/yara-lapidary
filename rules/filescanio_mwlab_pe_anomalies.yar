// Vendored copy of a public rule, not original work of this repository.
// Source: https://github.com/filescanio/fsYara-original/blob/b79ac8ba9ca9e14843e9f5d0d89a07d6f9bb06b7/executable/PE-ELF/generic/mwlab-pe-anomalies.yar
// Pinned: https://raw.githubusercontent.com/filescanio/fsYara-original/b79ac8ba9ca9e14843e9f5d0d89a07d6f9bb06b7/executable/PE-ELF/generic/mwlab-pe-anomalies.yar
// Author: filescanio
// License: unspecified
// Fetched: 2026-11-26
// Techniques: entropy-range, match-offset-arithmetic, module-iterator, nested-loop, non-pe-module, pe-structure, read-arithmetic
// Expect: warn

import "pe"
import "time"
import "math"
import "dotnet"

///// pe header /////

//rule pe_timestamp_in_future
//{
//    meta:
//        description = "PE TimeDateStamp is set in future"
//        score = 50
//
//    condition:
//        pe.is_pe and
//        pe.timestamp > time.now() and
//        pe.timestamp - time.now() > 86400  // more than 1 day ahead
//}


// trigger with many benign samples
//rule pe_no_checksum
//{
//    meta:
//        description = "PE checksum is not set"
//
//    condition:
//        pe.is_pe and
//        pe.checksum == 0
//}


//rule pe_invalid_checksum
//{
//    meta:
//        description = "PE checksum is invalid"
//
//    condition:
//        pe.is_pe and
//        pe.checksum != 0 and
//        pe.checksum != pe.calculate_checksum()
//}


//rule pe_susp_number_data_directories
//{
//    meta:
//        description = "PE with non common number of data directories value"
//        score = 50
//
//    condition:
//	   pe.is_pe and
//	   pe.number_of_rva_and_sizes != 16
//}

//rule pe_unusual_entrypoint_section
//{
//    meta:
//        description = "First section is not entrypoint section"
//        score = 50
//    condition:
//        pe.is_pe and
//        pe.entry_point != 0 and
//        not pe.is_dll() and
//        not (pe.entry_point >= pe.sections[0].raw_data_offset and
//         pe.entry_point <  pe.sections[0].raw_data_offset + pe.sections[0].raw_data_size)
//}

//rule pe_characteristics_dll_but_not_dll
//{
//    meta:
//        description = "PE has DLL characteristic flag set but lacks export directory"
//        score = 50
//
//    condition:
//        not dotnet.is_dotnet and
//        pe.is_pe and
//        pe.characteristics & pe.DLL and
//        pe.number_of_exports == 0
//        and for any section in pe.sections: // revome common fp: dll with only resources
//            (
//                section.name == ".text" or section.name == ".code"
//            )
//}



///// sections /////

//rule pe_number_of_sections_uncommon
//{
//    meta:
//        description = "PE has an unusual number of sections (<2 or >10)"
//        score = 50
//
//    condition:
//        not dotnet.is_dotnet and
//        pe.is_pe and
//        not pe.is_dll() and
//        (
//            pe.number_of_sections < 2 or
//            pe.number_of_sections > 10
//        )
//}


//rule pe_purely_vrtl_executable_section
//{
//    meta:
//        description = "PE section is executable, purely vrtl (SizeOfRawData == 0)"
//        score = 50
//
//    condition:
//        pe.is_pe and
//        for any section in pe.sections:
//            (
//                section.raw_data_size == 0 and
//                section.virtual_size > 0 and
//                	(
//                		section.characteristics & pe.SECTION_CNT_CODE != 0 or
//                		section.characteristics & pe.SECTION_MEM_EXECUTE != 0
//                	)
//            )
//}

//rule pe_purely_physical_section
//{
//    meta:
//        description = "PE section is physical-only and will not be mapped in memory"
//        score = 50
//
//    condition:
//        pe.is_pe and
//        for any section in pe.sections:
//            (
//                section.raw_data_size > 0 and
//                section.virtual_size == 0
//            )
//}

//rule pe_unbalanced_vrtl_physical_ratio
//{
//    meta:
//        description = "PE section with large difference between physical and vrtl size"
//        score = 50
//
//    condition:
//    	pe.is_pe and
//        for any section in pe.sections:
//            (
//                section.raw_data_size > 0 and
//                section.virtual_size > 0 and
//                (
//                    section.virtual_size > section.raw_data_size + 0x10000 or
//                    section.raw_data_size > section.virtual_size + 0x10000
//                )
//            )
//}

//rule pe_section_wx
//{
//    meta:
//        description = "PE section is both executable and writable"
//
//    condition:
//        pe.is_pe and
//        for any section in pe.sections:
//            (
//                section.characteristics & pe.SECTION_MEM_EXECUTE != 0 and
//                section.characteristics & pe.SECTION_MEM_WRITE != 0
//            )
//}

//rule pe_section_rwx
//{
//    meta:
//        description = "PE section is readable, executable and writable"
//        score = 50
//
//    condition:
//        pe.is_pe and
//        for any section in pe.sections:
//            (
//                section.characteristics & pe.SECTION_MEM_READ != 0 and
//                section.characteristics & pe.SECTION_MEM_EXECUTE != 0 and
//                section.characteristics & pe.SECTION_MEM_WRITE != 0
//            )
//}

//rule pe_section_no_name
//{
//    meta:
//        description = "PE section name is empty"
//
//    condition:
//        pe.is_pe and
//        for any section in pe.sections:
//        	(
//            	section.name == ""
//            )
//}

//rule pe_executable_section_and_no_code
//{
//    meta:
//        description = "PE executable section is flagged as not containing code"
//        score = 50
//
//    condition:
//        pe.is_pe and
//        for any section in pe.sections:
//            (
//                section.characteristics & pe.SECTION_MEM_EXECUTE != 0 and
//                section.characteristics & pe.SECTION_CNT_CODE == 0
//            )
//}

//rule pe_code_section_and_no_executable
//{
//    meta:
//        description = "PE section is marked as code but is not executable"
//        score = 50
//
//    condition:
//        pe.is_pe and
//        for any section in pe.sections:
//            (
//                section.characteristics & pe.SECTION_CNT_CODE != 0 and
//                section.characteristics & pe.SECTION_MEM_EXECUTE == 0
//            )
//}

//rule pe_high_ntrpy_section
//{
//    meta:
//        description = "PE file with section ntrpy higher than 7"
//        score = 50
//
//    condition:
//        pe.is_pe and
//        for any section in pe.sections:
//        	(
//            	math.entropy(section.raw_data_offset, section.raw_data_size) >= 7
//            )
//}

// more common in benign samples than expected
//rule pe_multiple_executable_sections
//{
//    meta:
//        description = "PE has more than one section with execute permissions"
//
//    condition:
//        pe.is_pe and
//        (
//            for any i in (0 .. pe.number_of_sections - 1) :
//                (
//                    pe.sections[i].characteristics & pe.SECTION_MEM_EXECUTE != 0 and
//                    for any j in (i + 1 .. pe.number_of_sections - 1) :
//                        (
//                            pe.sections[j].characteristics & pe.SECTION_MEM_EXECUTE != 0
//                        )
//                )
//        )
//}


rule pe_overlapping_sections
{
    meta:
        description = "PE sections have overlapping vrtl or raw addresses"
        score = 50

    condition:
        pe.is_pe and
        for any i in (0 .. pe.number_of_sections - 1) :
        	(
	            for any j in (i + 1 .. pe.number_of_sections - 1) :
	                (
                        (
                            pe.sections[i].virtual_address != 0 and pe.sections[j].virtual_address != 0 and
                            pe.sections[i].virtual_address + pe.sections[i].virtual_size > pe.sections[j].virtual_address
                        )

	                    or

                        (
	                       pe.sections[i].raw_data_offset != 0 and pe.sections[j].raw_data_offset != 0 and
	                       pe.sections[i].raw_data_offset + pe.sections[i].raw_data_size > pe.sections[j].raw_data_offset
                        )
	                )
        	)
}


///// imports /////

//rule pe_no_import_table
//{
//    meta:
//        description = "PE Import Table is missing"
//
//    condition:
//        not dotnet.is_dotnet and
//        pe.is_pe and
//        not pe.is_dll() and
//        (
//            pe.number_of_rva_and_sizes <= pe.IMAGE_DIRECTORY_ENTRY_IMPORT or
//            pe.data_directories[pe.IMAGE_DIRECTORY_ENTRY_IMPORT].virtual_address == 0 or
//            pe.data_directories[pe.IMAGE_DIRECTORY_ENTRY_IMPORT].size == 0
//        )
//}


//rule pe_zero_imports
//{
//    meta:
//        description = "PE does not imports functions"
//
//    condition:
//        not dotnet.is_dotnet and
//        pe.is_pe and
//        not pe.is_dll() and
//        pe.number_of_imported_functions == 0
//}


//rule pe_very_low_imports
//{
//    meta:
//        description = "PE imports few functions"
//
//    condition:
//        not dotnet.is_dotnet and
//        pe.is_pe and
//        not pe.is_dll() and
//        pe.number_of_imported_functions <= 5
//}


//rule pe_imports_by_ordinal
//{
//    meta:
//        description = "Detect PE imports using function ordinals (no named imports)"
//
//    condition:
//        pe.is_pe and
//        for any i in (0 .. pe.number_of_imports - 1) :
//        	(
//        		for any function in pe.import_details[i].functions :
//        			(
//        				function.name == "" and
//        				function.ordinal != 0
//        			)
//        	)
//}


//rule pe_gui_and_no_window_apis
//{
//    meta:
//        description = "PE with SUBSYSTEM_WINDOWS_GUI but no related imports"
//
//    condition:
//        not dotnet.is_dotnet and
//        pe.is_pe and
//        not pe.is_dll() and // fp
//        pe.subsystem == pe.SUBSYSTEM_WINDOWS_GUI and
//        (not pe.imports(/user32.dll/i,/(CreateWindow|CreateDialogIndirectParam|DialogBoxIndirectParam|DialogBoxParam|DispatchMessage|DefDlgProc|MessageBox|GetDC)/i) > 0
//        and
//        not pe.imports(/mscoree.dll/i,/\_CorExeMain/i) > 0 // avoid fp with dotnet
//        )
//}
//

//rule pe_dynamic_api_resolution_imports
//{
//    meta:
//        description = "PE imports few functions, including LoadLibrary and GetProcAddress"
//
//    condition:
//        pe.is_pe and
//        pe.number_of_imported_functions <= 5 and
//        pe.imports(/kernel32.dll/i, /loadlibrary(a|w)|getprocaddress/i) == 2
//}


//rule pe_dynamic_download_imports
//{
//    meta:
//        description = "Download API strings but not in import table"
//        score = 50
//
//    strings:
//    	$download_api = /internetreadfile|internetconnect[aw]|\brecvfrom\b/i
//
//    condition:
//        pe.is_pe and
//        #download_api > 0 and
//        not (pe.version_info["CompanyName"] contains "Microsoft" and pe.is_dll()) and // common fp
//        pe.imports(/wininet.dll/i, /internetreadfile|internetconnect[aw]/i) == 0 and
//        pe.imports(/ws2_32.dll/i, /recvfrom/i) == 0
//}


//rule pe_dynamic_crypto_imports
//{
//    meta:
//        description = "Crypto API strings but not in import table"
//        score = 50
//
//    strings:
//    	$crypto_api = /Crypt(ReleaseContext|AcquireContextA|DestroyHash|HashData|DestroyKey|DeriveKey|Encrypt|Decrypt)/i
//
//    condition:
//        pe.is_pe and
//        #crypto_api > 0 and
//        pe.imports(/advapi32.dll/i, /Crypt(ReleaseContext|AcquireContextA|DestroyHash|HashData|DestroyKey|DeriveKey|Encrypt|Decrypt)/i) == 0
//}

//rule pe_dynamic_injection_imports
//{
//    meta:
//        description = "Injection API strings but not in import table"
//        score = 50
//
//    strings:
//    	$injection_api = /(VirtualProtect(Ex)?|VirtualAlloc(Ex(Numa)?)?|ResumeThread|SetThreadContext|FindResourceA|LockResource|LoadResource|Ldr(AccessResource|FindResource_U)|Nt(ResumeThread|AllocateVirtualMemory|MapViewOfSection|ProtectVirtualMemory))/i
//
//    condition:
//        pe.is_pe and
//        #injection_api > 3 and
//        pe.imports(/kernel32.dll/i, /(VirtualProtect(Ex)?|VirtualAlloc(Ex(Numa)?)?|ResumeThread|SetThreadContext|FindResourceA|LockResource|LoadResource)/i) == 0 and
//        pe.imports(/ntdll.dll/i, /(Ldr(AccessResource|FindResource_U)|Nt(ResumeThread|AllocateVirtualMemory|MapViewOfSection|ProtectVirtualMemory))/i) == 0
//}


///// signature /////

// trigger with many benign samples
//rule pe_unsigned
//{
//    meta:
//        description = "PE without a digital certificate"
//    condition:
//        pe.is_pe and
//        pe.number_of_signatures == 0
//}

// rule pe_invalid_signature
// {
//     meta:
//         description = "PE signature is broken"

//     condition:
//         pe.is_pe and
//         pe.number_of_signatures > 0 and
//         not pe.is_signed // signature validation
// }

//rule pe_signature_expired
//{
//    meta:
//        description = "PE signature has expired"
//    condition:
//        pe.is_pe and
//        for any signature in pe.signatures:
//        	(
//            	signature.not_after < time.now()
//            )
//}

//rule pe_signature_expires_soon
//{
//    meta:
//        description = "PE signature expires soon"
//    condition:
//        pe.is_pe and
//        for any signature in pe.signatures:
//        	(
//            	not signature.not_after < time.now() and // covered with pe_signature_expired
//                signature.not_after < time.now() + 86400 * 15  // 15 days
//            )
//}


///// resources, overlay, and embedded files /////


//rule pe_high_ntrpy_resource_no_image
//{
//    meta:
//        description = "PE with embedded resource with high ntrpy (rcdata)"
//        score = 50
//
//    condition:
//        pe.is_pe and
//        pe.number_of_resources > 0 and
//        for any resource in pe.resources:
//        	(
//                resource.length > 1024 and
//                resource.type == pe.RESOURCE_TYPE_RCDATA and
//                math.entropy(resource.offset, resource.length) >= 7
//        	)
//}

//rule pe_large_overlay
//{
//    meta:
//        description = "PE with a large overlay"
//        score = 50
//
//    condition:
//        pe.is_pe and
//        pe.overlay.size > 20480 // 20KB
//}

//rule pe_high_ntrpy_overlay
//{
//    meta:
//        description = "PE overlay with high ntrpy"
//        score = 50
//
//    strings:
//        $cert_crl = "http://crl."
//
//    condition:
//        pe.is_pe and
//        pe.overlay.size > 1024 and
//        $cert_crl in (pe.overlay.offset..pe.overlay.size) and // fp overlay != signature
//        math.entropy(pe.overlay.offset, pe.overlay.size) >= 7
//}

//rule pe_embedded_pe
//{
//    meta:
//        description = "Discover embedded PE files, without relying on easily stripped/modified header strings."
//        score = 50
//    strings:
//        $mz = { 4D 5A }
//    condition:
//        for any i in (1..#mz):
//        (
//            @mz[i] != 0 and uint32(@mz[i] + uint32(@mz[i] + 0x3C)) == 0x00004550
//        )
//}

//rule pe_embedded_x509_cert
//{
//  meta:
//    description = "detect executable that likely have an embedded x509 certificate"
//    score = 50
//
//  strings:
//    $cert = "BEGIN CERTIFICATE" nocase ascii wide
//    $cert_xor = "BEGIN CERTIFICATE" xor(0x01-0xff)
//    $cert_base64 = "BEGIN CERTIFICATE" base64 base64wide
//    $cert_flipflop = "EBIG NECTRFICITAE" nocase ascii wide
//    $cert_reverse = "ETACIFITREC NIGEB" nocase ascii wide
//    $cert_hex = "424547494e204345525449464943415445" nocase ascii wide
//
//  condition:
//  	pe.is_pe and
//    any of them
//}

rule pe_resource_reversed_pe
{
  meta:
    description = "check for MZ at the end of the of any resource"
    score = 75

  condition:
  	pe.is_pe and
    for any resource in pe.resources:
    (
        uint16be((resource.offset + resource.length) - 2 ) == 0x5a4d
    )
}

rule pe_overlay_reversed_pe
{
  meta:
    description = "check for MZ at the end of the of the overlay"
    score = 75

  condition:
  	pe.is_pe and
    pe.overlay.offset != 0x0 and
    uint16be((pe.overlay.offset + pe.overlay.size) - 2) == 0x5a4d
}

rule pe_resource_base64d_pe
{
  meta:
    description = "looking for probable base64 encoded PE headers in the resources"
    score = 75

  condition:
  	pe.is_pe and
    for any resource in pe.resources: (
      uint32be(resource.offset) == 0x54567151 and // TVqQAAMA
      uint32be(resource.offset + 4) == 0x41414D41 // AAAEAAAA
    )
}


rule pe_overlay_base64d_pe
{
  meta:
    description = "looking for probable base64 encoded PE headers in the overlay"
    score = 75

  condition:
  	pe.is_pe and
    pe.overlay.offset != 0x0 and
    uint32be(pe.overlay.offset) == 0x54567151 and  // TVqQAAMA
    uint32be(pe.overlay.offset + 4) == 0x41414D41 // AAAEAAAA

}


rule pe_resource_single_byte_xor_PE
{
  meta:
    description = "Try the 3rd byte as a XOR key, since typically that byte is zero in a PE, meaning in encoded form it will contain the XOR key"

  condition:
  	pe.is_pe and
    for any resource in pe.resources: (
    	uint16(resource.offset) != 0x5a4d and
	    uint8(resource.offset) ^ uint8(resource.offset + 3) == 0x4d and
	    uint8(resource.offset+1) ^ uint8(resource.offset + 3) == 0x5a
    )
}

rule pe_overlay_single_byte_xor_PE
{
  meta:
    description = "Try the 3rd byte as a XOR key, since typically that byte is zero in a PE, meaning in encoded form it will contain the XOR key"
    score = 75

  condition:
  	pe.is_pe and
  	pe.overlay.offset != 0x0 and
  	uint16(pe.overlay.offset) != 0x5a4d and
  	int8(pe.overlay.offset) ^ uint8(pe.overlay.offset + 3) == 0x4d and
  	uint8(pe.overlay.offset+1) ^ uint8(pe.overlay.offset + 3) == 0x5a
}

rule pe_hex_encoded_pe
{
  meta:
    description = "Check for the bytes typically associated with a PE header, but as strings to detect hex encoding"
    score = 50

  strings:
    $dos_message_hex = "546869732070726f6772616d2063616e6e6f742062652072756e20696e20444f53206d6f6465" ascii wide nocase
    $mz_hex = "4D5A90000300" nocase ascii wide

  condition:
    all of them
}

rule pe_xored_dos_message
{
	meta:
        description = "Check xored dos message"
        score = 50

    strings:
        $dos_message = "This program cannot be run in DOS mode" xor(0x01-0xff) ascii wide

    condition:
        any of them
}


rule pe_base64d_pe
{
  meta:
    description = "Detects base64 encoded PE files"
    score = 50

 strings:
    $mz_header = "TVqQ"
    $this_program = "VGhpcyBwcm9ncmFt"
    $null_bytes = "AAAAA"

 condition:
    $mz_header and $this_program and #null_bytes > 2
}

rule pe_reversed_base64d_pe
{
  meta:
    description = "Detects reversed base64 encoded PE files"
    score = 50

 strings:
    $mz_header = "QqVT"
    $this_program = "tFmcn9mcwBycphGV"
    $null_bytes = "AAAAA"

 condition:
    $mz_header and $this_program and #null_bytes > 2
}


rule pe_double_base64d_pe
{
   meta:
      description = "Detects an executable that has been encoded with base64 twice"
      score = 75

   strings:
      $ = "VkdocGN5QndjbTluY21GdElHTmhibTV2ZENCaVpTQnlkVzRnYVc0Z1JFOVRJRzF2Wk" ascii wide
      $ = "ZHaHBjeUJ3Y205bmNtRnRJR05oYm01dmRDQmlaU0J5ZFc0Z2FXNGdSRTlUSUcxdlpH" ascii wide
      $ = "WR2hwY3lCd2NtOW5jbUZ0SUdOaGJtNXZkQ0JpWlNCeWRXNGdhVzRnUkU5VElHMXZaR" ascii wide
      $ = "Um9hWE1nY0hKdlozSmhiU0JqWVc1dWIzUWdZbVVnY25WdUlHbHVJRVJQVXlCdGIyUm" ascii wide
      $ = "JvYVhNZ2NISnZaM0poYlNCallXNXViM1FnWW1VZ2NuVnVJR2x1SUVSUFV5QnRiMlJs" ascii wide
      $ = "Sb2FYTWdjSEp2WjNKaGJTQmpZVzV1YjNRZ1ltVWdjblZ1SUdsdUlFUlBVeUJ0YjJSb" ascii wide
      $ = "VWFHbHpJSEJ5YjJkeVlXMGdZMkZ1Ym05MElHSmxJSEoxYmlCcGJpQkVUMU1nYlc5a1" ascii wide
      $ = "VhR2x6SUhCeWIyZHlZVzBnWTJGdWJtOTBJR0psSUhKMWJpQnBiaUJFVDFNZ2JXOWta" ascii wide
      $ = "VYUdseklIQnliMmR5WVcwZ1kyRnVibTkwSUdKbElISjFiaUJwYmlCRVQxTWdiVzlrW" ascii wide
      $ = "VkdocGN5QndjbTluY21GdElHMTFjM1FnWW1VZ2NuVnVJSFZ1WkdWeUlGZHBiak15" ascii wide
      $ = "ZHaHBjeUJ3Y205bmNtRnRJRzExYzNRZ1ltVWdjblZ1SUhWdVpHVnlJRmRwYmpNe" ascii wide
      $ = "WR2hwY3lCd2NtOW5jbUZ0SUcxMWMzUWdZbVVnY25WdUlIVnVaR1Z5SUZkcGJqTX" ascii wide
      $ = "Um9hWE1nY0hKdlozSmhiU0J0ZFhOMElHSmxJSEoxYmlCMWJtUmxjaUJYYVc0ek" ascii wide
      $ = "JvYVhNZ2NISnZaM0poYlNCdGRYTjBJR0psSUhKMWJpQjFibVJsY2lCWGFXNHpN" ascii wide
      $ = "Sb2FYTWdjSEp2WjNKaGJTQnRkWE4wSUdKbElISjFiaUIxYm1SbGNpQlhhVzR6T" ascii wide
      $ = "VWFHbHpJSEJ5YjJkeVlXMGdiWFZ6ZENCaVpTQnlkVzRnZFc1a1pYSWdWMmx1TX" ascii wide
      $ = "VhR2x6SUhCeWIyZHlZVzBnYlhWemRDQmlaU0J5ZFc0Z2RXNWtaWElnVjJsdU16" ascii wide
      $ = "VYUdseklIQnliMmR5WVcwZ2JYVnpkQ0JpWlNCeWRXNGdkVzVrWlhJZ1YybHVNe" ascii wide
   condition:
      1 of them
}