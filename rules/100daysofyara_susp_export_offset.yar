// Vendored copy of a public rule, not original work of this repository.
// Source: https://github.com/100DaysofYARA/2023/blob/5b630f980191cc4d06a96895734cd54815dd0877/glesnewich/SUSP_Export_Offset.yar
// Pinned: https://raw.githubusercontent.com/100DaysofYARA/2023/5b630f980191cc4d06a96895734cd54815dd0877/glesnewich/SUSP_Export_Offset.yar
// Author: 100DaysofYARA
// License: unspecified
// Fetched: 2026-11-26
// Techniques: defined, module-iterator, pe-structure
// Expect: pass

import "pe"

rule SUSP_Export_Offset_Zero
{
    meta:
        author = "Greg Lesnewich"
        description = "check for files that have at least 1 export that has an offset of 0"
        date = "2023-01-14"
        version = "1.0"
        DaysofYARA = "14/100"

    condition:
        for any exp in pe.export_details: (
            exp.offset == 0 and
            not defined exp.name  and
            not defined exp.forward_name
        )
}


rule SUSP_Export_Offset_Undefined
{
    meta:
        author = "Greg Lesnewich"
        description = "check for files that have at least 1 export that has an no defined offset or other fields"
        date = "2023-01-14"
        version = "1.0"
        DaysofYARA = "14/100"

    condition:
        for any exp in pe.export_details: (
            not defined exp.offset and
            not defined exp.name  and
            not defined exp.forward_name
        )
}
