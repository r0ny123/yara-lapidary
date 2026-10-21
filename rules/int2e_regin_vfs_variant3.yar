// Vendored copy for study. Not original work of this repository.
// Source:   https://gist.github.com/1nt2e/7fdcf7dee7e9948958b488d8a1e6e92a
// Pinned:   https://gist.githubusercontent.com/1nt2e/7fdcf7dee7e9948958b488d8a1e6e92a/raw/08366abaadcaba290f694ec1bfdf925d5747a59a/regin_vfs.yar
// Author:   1nt2e
// License:  unspecified (as declared by the source; see it for terms)
// Fetched:  2026-10-21

import "math"

rule Regin_VFS_variant3 {

    meta:
        author      = "@int2e_"
        description = "Hits on files matching Regin vfs structure - verifies header and loops through all files looking for entropy in first sector"
        reference   = "https://twitter.com/Int2e_/status/1483924698270425090"
        sample      = "b6893cfde5cd9050d087bb163d645fcd3d5f8324c5a7762d8e676564bcadfb0e"

    condition:
        filesize > 100000 and filesize < 100MB

        and
        // sector size
        (uint16(0) == 0x100 or uint16(0) == 0x200
        or uint16(0) == 0x400 or uint16(0) == 0x800)

        and
        // max number of sectors
        (uint16(2) == 0x800 or uint16(2) == 0x1000)

        and
        // crc32 of the first file not 0
        uint32((uint16(2)\8)+0x13) != 0

        and
        // size of the first file not 0
        uint32(uint16(2)\8+0x13+4) != 0

        and
        // offset of the first file's first block not 0
        uint32(uint16(2)\8+0x13+8) != 0

        and
        // size of id field:
        uint8(6) > 0 and uint8(6) <= 8

        and
        // id of the first file not 0 (value below uses arbitrary size(id) of 4 but this does not really matter)
        uint32(uint16(2)\8+0x13+8+12) != 0

        and
        // number of files in the vfs > 0 and lower than 4096 because why not
        uint16(0xf) > 0 and uint16(0xf) < 0x1000

        and
        // for all files in vfs, check:
        // - that the first sector has entropy and next links to another sector
        // - or that it has a size lower than sector size and next points to nothing
        for (uint16(0xf)) i in (0 .. uint16(0xf)-1) :(
            (
                uint32( uint16(2)\8+0x13+4 + i * (12+uint8(6)) ) <= uint16(0) // size of data <= size of sector
                and
                uint32( uint32( uint16(2)\8+0x13+8 + i * (12+uint8(6)) ) ) == 0 // offset of next data == 0
            )
            or
            (
                math.entropy(
                    uint32( uint16(2)\8+0x13+8 + i * (12+uint8(6)) ) +4,
                    uint32( uint16(2)\8+0x13+4 + i * (12+uint8(6)) ) -4
                ) > 7.9 // entropy of first sector > 7.9
                and
                (
                    uint32( uint16(2)\8+0x13+4 + i * (12+uint8(6)) ) > uint16(0) // size of file > size of sector
                    and
                    uint32( uint16(2)\8+0x13+8 + i * (12+uint8(6)) ) + uint16(0) == uint32( uint32( uint16(2)\8+0x13+8 + i * (12+uint8(6)) ) ) // next sector should be += sector size
                )
            )
        )
}