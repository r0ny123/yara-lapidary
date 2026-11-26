// Vendored copy of a public rule, not original work of this repository.
// Source: https://github.com/100DaysofYARA/2026/blob/5826ee2066d3840a0293dff1d43b34202326b661/RustyNoob619/Day4.yara
// Pinned: https://raw.githubusercontent.com/100DaysofYARA/2026/5826ee2066d3840a0293dff1d43b34202326b661/RustyNoob619/Day4.yara
// Author: 100DaysofYARA
// License: MIT
// Fetched: 2026-11-26
// Techniques: entropy-range, pe-structure
// Expect: pass

import "pe"
import "math"

rule SUS_WIN_PE_TamperedRichHeader_PE_Properties_Jan26
{
    meta:
        rule_id = "0678a71c-e8c9-4dba-93b6-342d1ad07dd9"
        date = "04-01-2026"
        author = "Rustynoob619"
        description = "Detects Windows PE files with potentially duplicated Rich headers. This is based on the fact that there can only exist unique pairs of ProdIDs and Build numbers. Hence, the overall enthropy or randomness should be high"
        source = "https://www.virusbulletin.com/virusbulletin/2020/01/vb2019-paper-rich-headers-leveraging-mysterious-artifact-pe-format/"

    condition:
        uint16(0) == 0x5a4d
        and pe.rich_signature.length > 0
        and math.entropy(pe.rich_signature.clear_data) < 1
        and filesize < 10MB 
}
