// Vendored copy for study. Not original work of this repository.
// Source:   https://gist.github.com/edeca/e8f05c457439a4f13e85f4b2dc68aa38
// Pinned:   https://gist.githubusercontent.com/edeca/e8f05c457439a4f13e85f4b2dc68aa38/raw/72f8851dc474cffad941f1fd1dd1385f09e64851/dll_multiple_exports_same_rva_patch.yar
// Author:   edeca
// License:  unspecified (as declared by the source; see it for terms)
// Fetched:  2026-10-21

// This rule uses a feature of Yara from a proposed new feature, see:
// https://github.com/wxsBSD/yara/tree/export_addresses

import "math"
import "pe"

rule multiple_exports_same_rva {
  condition:
    pe.characteristics & pe.DLL and
    pe.number_of_exports > 1 and
    for any i in (0 .. math.min(256, pe.number_of_exports) - 2) : (
      // Ensure it's not forwarded
      pe.export_details[i].offset > 0 and

      for any j in (i + 1 .. math.min(256, pe.number_of_exports) - 1) : (
        pe.export_details[i].offset == pe.export_details[j].offset
      )
    )
}