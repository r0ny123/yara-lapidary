// Vendored copy of a public rule, not original work of this repository.
// Source: https://github.com/evild3ad/yara/blob/343258ef1cc155c060c4505c220f0e6fc9614300/evild3ad/Windows_Suspicious_Authenticode.yar
// Pinned: https://raw.githubusercontent.com/evild3ad/yara/343258ef1cc155c060c4505c220f0e6fc9614300/evild3ad/Windows_Suspicious_Authenticode.yar
// Author: evild3ad
// License: GPL-3.0
// Fetched: 2026-11-26
// Techniques: defined, module-iterator
// Expect: warn

import "pe"

rule Windows_Suspicious_Authenticode_Known_Abused_Cert : Authenticode {
    meta:
        description = "Detects PE files signed with code-signing certificates known to be abused for malware and revoked by the issuer (serial + issuer)"
        author = "Martin Willing (https://lethal-forensics.com)"
        id = "acb998a2-08e8-4805-b078-34081886f578"
        creation_date = "2026-11-04"
        last_modified = "2026-11-04"
        threat_name = "Windows.Suspicious.Authenticode"
        severity = 90
        arch_context = "x86, x64"
        scan_context = "file"
        os = "windows"
    condition:
        // the Authenticode signature is not mapped into process memory: scan files (e.g. M:\forensic\files)
        uint16(0) == 0x5A4D and filesize < 200MB and
        for any s in pe.signatures : (
            // "YOUR CHANCE j.d.o.o" (EV, HR), valid 2026-09-11 - 2027-09-11, revoked
            // SHA-1 thumbprint 4cee19bfbfbd3ff809829fa7315d4c0246a26a19
            (
                s.serial == "00:a7:df:46:af:2d:89:7f:f9:1b:38:c5:de:7e:fb:c3:31" and
                s.issuer contains "Sectigo Public Code Signing CA EV R36"
            )
        )
}

rule Windows_Suspicious_Authenticode_Young_EV_Cert_Mismatch : Authenticode {
    meta:
        description = "Hunts for PE files signed with a freshly issued EV code-signing certificate (< 60 days before signing) whose signer does not match the CompanyName in the version info, or that have no CompanyName at all"
        author = "Martin Willing (https://lethal-forensics.com)"
        id = "a652d1d6-c77b-48e7-a7a9-f49cfd713cec"
        creation_date = "2026-11-04"
        last_modified = "2026-11-04"
        threat_name = "Windows.Suspicious.Authenticode"
        severity = 50
        arch_context = "x86, x64"
        scan_context = "file"
        os = "windows"
    condition:
        // Hunting Rule: Verify hits with sigcheck / Get-AuthenticodeSignature (Revocation Status)
        // Microsoft rotates its signing certificates every few weeks and is excluded.
        uint16(0) == 0x5A4D and filesize < 200MB and
        pe.number_of_signatures == 1 and
        for any s in pe.signatures : (
            not (s.issuer icontains "Microsoft") and
            s.subject contains "businessCategory=Private Organization" and
            // No Version Info (e.g. Rust/Go implants) or CompanyName not part of the Signer Subject
            (
                not defined pe.version_info["CompanyName"] or
                pe.version_info["CompanyName"] == "" or
                not (s.subject icontains pe.version_info["CompanyName"])
            ) and
            for any c in s.countersignatures : (
                c.sign_time > s.not_before and
                c.sign_time - s.not_before < 60 * 86400
            )
        )
}
