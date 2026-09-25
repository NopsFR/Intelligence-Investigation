// Differential fixture: rule set and the matches reported by yara-python 4.5.4
// for two inputs built in the test. The engine must agree exactly.

export const DIFF_RULES = "import \"pe\"\nimport \"math\"\nimport \"hash\"\n\nrule MZ_header { condition: uint16(0) == 0x5A4D }\nrule PE_sig { condition: uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550 }\nrule Text_nocase { strings: $a = \"hello\" nocase condition: #a >= 2 }\nrule Text_wide { strings: $a = \"PowerShell\" wide condition: $a }\nrule Text_ascii_wide { strings: $a = \"powershell\" nocase ascii wide condition: any of them }\nrule Fullword { strings: $a = \"fullword\" fullword $b = \"wordtest\" fullword condition: $a and not $b }\nrule Xor_str { strings: $a = \"cmd.exe\" xor condition: $a }\nrule Xor_range { strings: $a = \"cmd.exe\" xor(0x50-0x5f) condition: $a }\nrule B64 { strings: $a = \"This program cannot\" base64 condition: $a }\nrule Hex_wild { strings: $h = { 4D 5A ?? 00 [0-4] 00 } condition: $h at 0 }\nrule Hex_alt { strings: $h = { 50 45 00 00 ( 4C 01 | 64 86 ) } condition: $h }\nrule Hex_nibble { strings: $h = { 5? 45 00 00 } condition: #h > 0 }\nrule Hex_not { strings: $h = { 4D ~5B } condition: $h in (0..2) }\nrule Regex_i { strings: $r = /invoke-expression\\s*\\(/i condition: $r }\nrule Regex_url { strings: $r = /https?:\\/\\/[a-z0-9.\\-]+\\/[a-z]+/ condition: @r[1] > 10 and !r[1] > 10 }\nrule Of_them { strings: $a = \"hello\" $b = \"again\" $c = \"nomatchstring\" condition: 2 of them }\nrule Pct { strings: $a = \"hello\" $b = \"again\" $c = \"nomatchstring\" $d = \"world\" condition: 75% of them }\nrule None_of { strings: $a = \"zzzzqqq\" $b = \"qqqqzzz\" condition: none of them }\nrule For_of { strings: $a = \"hello\" $b = \"world\" condition: for all of ($a, $b) : ( $ in (0..20) ) }\nrule For_in { strings: $a = \"hello\" nocase condition: for any i in (1..#a) : ( @a[i] > 20 ) }\nrule Filesize_small { condition: filesize < 1KB }\nrule Math_entropy { condition: math.entropy(0, filesize) > 7.0 }\nrule Hash_md5 { condition: hash.md5(0, 2) == \"3b0f1c6d0f06cd2dcd3b36c7a9e0f09d\" or hash.md5(0, 2) == \"e0e44b6b9b7d0b7d8e14e0e8ad3a7fae\" }\nrule Pe_is64 { condition: pe.is_pe and pe.machine == pe.MACHINE_AMD64 }\nrule Pe_imports { condition: pe.imports(\"KERNEL32.dll\", \"GetProcAddress\") }\nrule Pe_sections { condition: pe.number_of_sections >= 5 and pe.sections[0].name == \".text\" }\nrule Pe_dll_char { condition: pe.dll_characteristics & pe.DYNAMIC_BASE }\nrule Rule_ref { condition: MZ_header and not Text_nocase }\nprivate rule Priv { strings: $a = \"world\" condition: $a }\nrule Uses_priv { condition: Priv and filesize > 10 }\nrule Offsets { strings: $a = \"o\" condition: #a in (0..50) >= 3 }\nrule Int_ops { condition: (uint8(0) | 0x20) == 0x6D or (uint8(0) ^ 0x70) == 0 }\nrule Str_ops { condition: pe.sections[0].name startswith \".te\" and pe.sections[0].name iequals \".TEXT\" }\n";

export const EXPECTED_CRAFTED: Record<string, string[]> = {
  "B64": [
    "$a:7:25"
  ],
  "Filesize_small": [],
  "Fullword": [
    "$a:106:8"
  ],
  "Int_ops": [],
  "None_of": [],
  "Text_ascii_wide": [
    "$a:71:20"
  ],
  "Text_wide": [
    "$a:71:20"
  ],
  "Xor_range": [
    "$a:48:7"
  ],
  "Xor_str": [
    "$a:48:7"
  ]
};

export const EXPECTED_TEXT: Record<string, string[]> = {
  "Filesize_small": [],
  "For_in": [
    "$a:0:5",
    "$a:91:5",
    "$a:103:5"
  ],
  "For_of": [
    "$a:0:5",
    "$a:91:5",
    "$b:6:5"
  ],
  "None_of": [],
  "Of_them": [
    "$a:0:5",
    "$a:91:5",
    "$b:97:5"
  ],
  "Offsets": [
    "$a:4:1",
    "$a:7:1",
    "$a:15:1",
    "$a:27:1",
    "$a:58:1",
    "$a:62:1",
    "$a:95:1"
  ],
  "Pct": [
    "$a:0:5",
    "$a:91:5",
    "$b:97:5",
    "$d:6:5"
  ],
  "Regex_i": [
    "$r:12:19"
  ],
  "Regex_url": [
    "$r:73:15"
  ],
  "Text_nocase": [
    "$a:0:5",
    "$a:91:5",
    "$a:103:5"
  ],
  "Uses_priv": []
};
