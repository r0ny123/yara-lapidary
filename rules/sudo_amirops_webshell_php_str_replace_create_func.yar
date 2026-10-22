// Vendored copy for study. Not original work of this repository.
// Source:   https://github.com/sudo-amirops/YARA-SIGMA-Rules-Collection/blob/460091196d632f58c7ef4a9573dbea4e6dcbd0bd/yara/webshells/webshell_php_str_replace_create_func.yar
// Pinned:   https://raw.githubusercontent.com/sudo-amirops/YARA-SIGMA-Rules-Collection/460091196d632f58c7ef4a9573dbea4e6dcbd0bd/yara/webshells/webshell_php_str_replace_create_func.yar
// Author:   sudo-amirops
// License:  unspecified (as declared by the source; see it for terms)
// Fetched:  2026-10-22

/*
 * ---------------------------------------------------------------
 *   source repo : volexity/threat-intel
 *   source url  : https://github.com/volexity/threat-intel
 *   source path : 2022/2022-06-15 DriftingCloud - Zero-Day Sophos Firewall Exploitation and an Insidious Breach/indicators/yara.yar
 *   commit      : a7eaa9d97a5d
 *   license     : BSD-2-Clause -- Permissive
 *   collected   : 2026-07-30
 *   rule author : threatintel@volexity.com
 *   repairs     : added missing import "math"
 * ---------------------------------------------------------------
 */
import "math"

rule webshell_php_str_replace_create_func
{
    meta:
        author = "threatintel@volexity.com"
        description = "Looks for obfuscated PHP shells where create_function() is obfuscated using str_replace and then called using no arguments."
        date = "2022-04-04"
        hash1 = "c713d13af95f2fe823d219d1061ec83835bf0281240fba189f212e7da0d94937"
        os = "win,linux"
        os_arch = "all"
        scan_context = "file"
        severity = "high"
        last_modified = "2025-06-18T15:11:16Z"
        license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
        rule_id = 6675
        version = 5

    strings:
        // $P=str_replace(
        $s = "=str_replace(" ascii
        // call it as a function
        // $S=$P('',$a);
        $anon_func = "(''," ascii

    condition:
        filesize < 100KB and
        uint32be(0) == 0x3c3f7068 and
        all of them and
        for any i in (1..math.min(#s,100)):
            (
                for any j in (1..math.min(#anon_func,100)):
                    (
                        uint16be(@s[i]-2) == uint16be(@anon_func[j]-2)
                    )
            )
}
