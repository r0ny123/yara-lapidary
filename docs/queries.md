# Finding candidate rules

GitHub web code search accepts RE2-style regexes between slashes with
`language:yara`, `path:`, `repo:`, `NOT` and `-qualifier`. The REST API
(`gh search code`) takes literal tokens only; use it to count how common a
construct is and the web UI to read the hits.

Noise exclusions for every query:
`NOT maldoc NOT generic_anomalies -repo:Neo23x0/signature-base -repo:Yara-Rules/rules -path:test -path:tests`

Inside `/.../` escape `\$ \( \) \[ \] \\ \/`. Keep regexes under about 150
characters.

| Construct | Query |
|---|---|
| `@a[i]` arithmetic | `/@[a-z_0-9]+\[[a-z0-9+ -]+\] *[-+<>=]/ language:yara` |
| match length | `/![a-z_0-9]+(\[[a-z0-9]+\])? *[-+<>=)]/ language:yara` |
| anonymous `@`/`!` in `for of` | `/for (any\|all\|[0-9]+) of \(\$[^)]*\) *: *\(.*(uint(8\|16\|32)\(@\|== *!\|@ *[-+] *@)/ language:yara` |
| pattern in computed window | `/\$[a-z_0-9]+ in \(@[a-z_0-9]+/ language:yara` |
| anchored to computed offset | `/\$[a-z_0-9]+ at (pe\.\|uint\|@\|\()/ language:yara` |
| counted range | `/#[a-z_0-9]+ in \(/ language:yara` |
| last occurrence | `/@[a-z_0-9]+\[#[a-z_0-9]+\]/ language:yara` |
| nested `for` | `/for (any\|all\|[0-9]+) [a-z_]+ in \([^)]*\) *: *\( *for /i language:yara` |
| bound read from file | `/for (any\|all\|[0-9]+) [a-z_]+ in \([^)]*uint(8\|16\|32)\(/ language:yara` |
| quantifier is an expression | `/for \(uint(8\|16\|32)\([^)]*\)\) [a-z_]+ in/ language:yara` |
| capped bounds | `/in \([^)]*math\.(min\|max)\(/ language:yara` |
| module array loops | `/for (any\|all\|[0-9]+) [a-z_]+ in (pe\|elf\|macho\|dotnet\|lnk\|dex)\.[a-z_]+ *:/ language:yara` |
| dictionary iteration | `/for (any\|all) [a-z_]+, *[a-z_]+ in /i language:yara` |
| `with` (YARA-X) | `/\bwith +[a-z_]+ *= *[a-z_.]+/ language:yara` |
| XOR between reads | `/uint(8\|16\|32)(be)?\([^)]*\) *\^ *uint/ language:yara` |
| integer division | `/uint(8\|16\|32)\([^)]*\) *\\ *[0-9]/ language:yara` |
| modulo | `/(filesize\|uint(8\|16\|32)\([^)]*\)) *% *(0x[0-9a-f]+\|[0-9]+)/ language:yara` |
| shifts and masks | `/uint(8\|16\|32)\([^)]*\) *(<<\|>>\|&) *(0x)?[0-9a-f]+/ language:yara` |
| pointer chasing | `/uint(16\|32)\(uint(16\|32)\([^)]*\) *[-+]/ language:yara` |
| reads relative to filesize | `/uint(8\|16\|32)(be)?\(filesize *-/ language:yara` |
| `defined` | `/\b(not )?defined (pe\|elf\|macho\|dotnet\|lnk)\./ language:yara` |
| hash over computed range | `/hash\.(md5\|sha1\|sha256\|crc32\|checksum32)\( *(pe\.\|@\|uint\|filesize)/ language:yara` |
| entropy over computed range | `/math\.(entropy\|mean\|mode\|percentage\|count)\( *(pe\.\|@\|uint)/ language:yara` |
| data-directory arithmetic | `/data_directories\[pe\.IMAGE_DIRECTORY_ENTRY_[A-Z_]+\]\.(virtual_address\|size) *[-+<>=]/ language:yara` |
| RVA conversion fed by a read | `/rva_to_offset\( *(uint32\|@)/ language:yara` |
| rich header | `/rich_signature\.(clear_data\|toolid\|version\|key\|offset)/ language:yara` |
| overlay arithmetic | `/overlay\.(offset\|size) *[-+<>=%]/ language:yara` |
| resource geometry | `/resources\[[0-9a-z]+\]\.(length\|offset\|rva) *[-+<>=]/ language:yara` |
| version-info dictionary | `/version_info\["[A-Za-z]+"\] *(==\|contains\|icontains\|matches)/ language:yara` |
| Mach-O hashes | `/macho\.(dylib_hash\|entitlement_hash\|export_hash\|symhash\|has_entitlement)/ language:yara` |
| ELF iterators | `/for (any\|all) [a-z_]+ in elf\.(symtab\|dynsym\|dynamic\|segments)/ language:yara` |
| .NET collections | `/dotnet\.(user_strings\|classes\|resources\|assembly_refs\|streams\|constants)/ language:yara` |
| console mining rules | `/console\.(log\|hex)\(/ language:yara` |
| nibble masks in alternatives | `/\( *[0-9A-Fa-f]\? *\|/ language:yara` |
| jumps inside alternatives | `/\( *[0-9A-Fa-f]{2}[^)]*\[[0-9]+-[0-9]*\][^)]*\|/ language:yara` |
| negated bytes | `/\{[^}]*~[0-9A-Fa-f?]{2}[^}]*\}/ language:yara` |
| mnemonic comments in hex | `/\{[^}]*\/\/ *(mov\|push\|call\|xor\|lea\|cmp\|jmp\|jn?e)\b/i language:yara` |
| long literal tables | `/\{( *[0-9A-Fa-f]{2}){96,}\s*\}/ language:yara` |
| `of` sets anchored or ranged | `/of \(\$[^)]*\) (in\|at) \(/ language:yara` |

Token counts via the API, for calibration (October 2026): `math.min` 36
files, `not defined` 20, `macho.dylib_hash` 6, `math.entropy` with
`rva_to_offset` 4, `rich_signature.clear_data` 166, `console.log` 432.

```bash
gh api -X GET search/code -f q='language:yara "math.min"' --jq '.total_count'
```

When reading hits: skip conditions that are `all of them` behind an MZ
check, follow the author rather than the repository, and compile anything
you keep before adding it to the index.
