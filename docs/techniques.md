# Technique vocabulary

Use these tags in `index/*.json`. Add a tag here before using it.

| Tag | Meaning |
|---|---|
| `known-plaintext` | XOR or arithmetic between positions whose plaintext is known, so the key cancels or is read off |
| `header-arithmetic` | chained `uintXX` reads following format pointers (e_lfanew, directories, tables) |
| `at-computed-offset` | `$a at <expression>` or `$a in (<expr>..<expr>)` |
| `match-offset-arithmetic` | `@a[i]`, `@a - @b`, distance or ordering constraints |
| `match-length` | `!a` or `!a[i]` used in the condition |
| `anonymous-match-vars` | `@` and `!` inside `for ... of` |
| `stride-loop` | proves periodicity of repeated records via `@a[i] + N == @a[i+1]` |
| `per-occurrence-parse` | loops over `@hdr[i]` and parses fields relative to each hit |
| `nested-loop` | a `for` inside a `for` |
| `file-derived-bound` | loop bound or quantifier read from the file, with a sanity cap |
| `capped-loop` | `math.min` / `math.max` on a loop range |
| `module-iterator` | `for x in pe.sections` and similar over module arrays |
| `pairwise-duplicate` | `i` / `i+1..` nested loop finding equal fields |
| `content-hash-range` | `hash.*` over a computed `(offset, size)` |
| `entropy-range` | `math.entropy` or similar over a computed range |
| `rich-header` | `pe.rich_signature` fields |
| `export-anomaly` | export table relationships (same RVA, missing names, first bytes) |
| `resource-geometry` | relationships between resource sizes, types, offsets |
| `overlay` | `pe.overlay` arithmetic |
| `length-audit` | declared size versus encoded size (certificate padding, sector math) |
| `structure-parser` | a container walked entirely by integer reads |
| `integrity-arithmetic` | size, CRC or alignment relations that must hold |
| `hex-alternatives` | `( A \| B )` encoding register, opcode or branch variation |
| `nibble-mask` | `A?` style masks |
| `variant-set` | one string per observed variant behind a shared anchor |
| `stack-string` | `mov [ebp+x], imm` chains spelling a string |
| `api-argument` | pushed arguments plus alternation over call forms |
| `string-encoding-battery` | sibling patterns per encoding (base64, xor, hex, reversed) |
| `negative-window` | `not $neg in (@a..@a + N)` |
| `defined` | use of the `defined` operator |
| `rule-reference` | a rule referenced inside another rule's condition |
| `macho`, `elf`, `dotnet`, `lnk`, `dex`, `crx` | module-specific techniques |
| `yara-x-only` | needs a YARA-X feature (`with`, `.len()`, Mach-O hashes) |
| `console-mining` | logger rules that print values to mine a corpus |
