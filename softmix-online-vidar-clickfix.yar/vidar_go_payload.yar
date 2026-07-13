import "pe"

rule softmix_Vidar_Go_Payload_Strict
{
    meta:
        description   = "Vidar (Go) final payload from softmix.online ClickFix chain — network IOC match"
        date          = "2026-07-13"
        tlp           = "CLEAR"
        confidence    = "high"
        hash_sha256   = "20d47f34fb6c5841bbebea4796b7b9fcc3f6920ef9d3be0530978f0cbc6e4d7"
        reference     = "softmix.online ClickFix -> Go infostealer"

    strings:
        // --- HIGH confidence: observed directly in the disassembly (slide 13) ---
        $steam_resolver = "steamcommunity.com/profiles/76561198680197300" ascii   // dead-drop resolver
        $c2_url         = "https://5.75.217.106"                            ascii
        $c2_ip          = "5.75.217.106"                                    ascii

        // --- Go build fingerprint ---
        $go_buildinf    = { FF 20 47 6F 20 62 75 69 6C 64 69 6E 66 3A }            // "\xff Go buildinf:"
        $go_ver         = "go1.25.4"                                        ascii

    condition:
        pe.machine == pe.MACHINE_AMD64
        and filesize < 8MB
        and $go_buildinf
        and (
            $steam_resolver                 // strongest single indicator
            or $c2_url
            or ( $c2_ip and $go_ver )       // gate the bare IP behind the Go build to cut FP
        )
}

rule softmix_Vidar_Go_Payload_Structural
{
    meta:
        description   = "Vidar (Go) softmix payload — Garble build + symbol-table fingerprint"
        author        = "Shreethaar"
        date          = "2026-07-13"
        tlp           = "CLEAR"
        confidence    = "medium (build-artifact based; may match sibling builds only)"
        hash_sha256   = "20d47f34fb6c5841bbebea4796b7b9fcc3f6920ef9d3be0530978f0cbc6e4d7"

    strings:
        $go_buildinf = { FF 20 47 6F 20 62 75 69 6C 64 69 6E 66 3A }
        $mod         = "VUHeVADnCfYOMnEgqssI" ascii
        $sec_symtab  = ".symtab"       ascii
        $sec_coff    = "COFF_SYMBOLS"  ascii
        $fn_apires   = "ifecveeoeamm"        ascii   // LazyProc dynamic API resolver
        $fn_bf1      = "lrcpvlvcnsefxgjdf"    ascii   // decoy interpreter
        $fn_prng     = "jsekgkzhqdxtkrzb"     ascii   // SplitMix64 PRNG
        $fn_set      = "qlmwnose"             ascii   // boolean set-logic
        $fn_bf2      = "qyhmqay"              ascii   // decoy interpreter
        $cert        = "gusto.it"             ascii

    condition:
        pe.machine == pe.MACHINE_AMD64
        and filesize < 8MB
        and $go_buildinf
        and (
            $mod                                        // module name alone is specific
            or 3 of ($fn_*)                             // 3+ of the obfuscated fn names
            or ( $sec_symtab and $sec_coff and $cert )  // symtab-retained + abused cert
        )
}

rule Garble_Obfuscated_Go_PE_Hunting
{
   
    meta:
        description = "Hunting: Garble-obfuscated Go PE (high FP — triage only)"
        author      = "Shreethaar"
        date        = "2026-07-13"
        tlp         = "CLEAR"
        confidence  = "hunting-only"

    strings:
        $go_buildinf = { FF 20 47 6F 20 62 75 69 6C 64 69 6E 66 3A }
        $go_runtime1 = "runtime.main"       ascii
        $go_runtime2 = "runtime.gopanic"    ascii
        $go_ver_re   = /go1\.2[0-9](\.[0-9]{1,2})?/ ascii
        $garble_tok1 = "ifecveeoeamm"    ascii
        $garble_tok2 = "jsekgkzhqdxtkrzb" ascii

    condition:
        pe.machine == pe.MACHINE_AMD64
        and filesize < 20MB
        and $go_buildinf
        and any of ($go_runtime*)
        and ( $go_ver_re or any of ($garble_tok*) )
}
