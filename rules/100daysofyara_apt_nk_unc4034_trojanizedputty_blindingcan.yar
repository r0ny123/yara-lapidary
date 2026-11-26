// Vendored copy of a public rule, not original work of this repository.
// Source: https://github.com/100DaysofYARA/2022/blob/f86e11869c36a0662b1eb26f09086ad530c50f17/glesnewich/APT_NK_UNC4034_TrojanizedPutty_BLINDINGCAN.yar
// Pinned: https://raw.githubusercontent.com/100DaysofYARA/2022/f86e11869c36a0662b1eb26f09086ad530c50f17/glesnewich/APT_NK_UNC4034_TrojanizedPutty_BLINDINGCAN.yar
// Author: 100DaysofYARA
// License: unspecified
// Fetched: 2026-11-26
// Techniques: content-hash-range, module-iterator, pe-structure
// Expect: fail

rule APT_NK_UNC4034_TrojanizedPutty_BLINDINGCAN {

    meta:
        description = "track trojanized instances of Putty dropping BLINDINGCAN"
        author = "Greg Lesnewich"
        date = "2022-09-15"
        version = "1.0"
        reference = "https://www.mandiant.com/resources/blog/dprk-whatsapp-phishing"
        hash = "cf22964951352c62d553b228cf4d2d9efe1ccb51729418c45dc48801d36f69b4"
        hash = "1492fa04475b89484b5b0a02e6ba3e52544c264c294b57210404b96b65e63266"
    strings:
        $exe1 = "schtasks.exe"
        $exe2 = "C:\\ProgramData\\PackageColor\\colorcpl.exe"
        $schtask = "/CREATE /SC DAILY /MO 1 /ST 10:30 /TR"
        $sc1 = "/CREATE /SC"
        $sc2 = "DAILY /MO 1"
        $sc3 = "/ST 10:30 /TR"
        $sc4 = "/TN PackageColor /F"

    condition:
        all of ($exe*) and ($schtask or 3 of ($sc*)) and
        pe.version_info["OriginalFilename"] == "PuTTY"
        and hash.md5(pe.rich_signature.clear_data) == "abe46a9066a76a1ae9e5d70262510bda"
        and for any rsrc in pe.resources: (hash.sha256(rsrc.offset, rsrc.length) == "89101ef80cb32eccdb988e8ea35f93fe4c04923023ad5c9d09d6dbaadd238073")

}
