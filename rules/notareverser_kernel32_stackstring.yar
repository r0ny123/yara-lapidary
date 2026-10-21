// Vendored copy for study. Not original work of this repository.
// Source:   https://gist.github.com/notareverser/eb2a7cf37e6cd64b817212aba9b556eb
// Pinned:   https://gist.githubusercontent.com/notareverser/eb2a7cf37e6cd64b817212aba9b556eb/raw/81e9e1a40e069ed9ea1de11418c05420d1f348e6/kernel32.yara
// Author:   notareverser
// License:  unspecified (as declared by the source; see it for terms)
// Fetched:  2026-10-21

rule stackstring_kernel32_large_stack
{
  strings:
    $v = { c785[1-4]6b[3-4]
           c785[1-4]65[3-4]
           c785[1-4]72[3-4]
           c785[1-4]6e[3-4]
           c785[1-4]65[3-4]
           c785[1-4]6c[3-4]
           c785[1-4]33[3-4]
           c785[1-4]32[3-4]
           c785[1-4]2e[3-4]
           c785[1-4]64[3-4]
           c785[1-4]6c[3-4]
           c785[1-4]6c??????}
            condition: $v	 
}