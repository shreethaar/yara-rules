rule Softmix_PS1_Dropper
{
    meta:
        description = "First-stage PowerShell dropper (softmix.online fake installer)"
        date        = "2026-07-04"
    strings:
        $u1 = "softmix.online/ps" ascii wide nocase
        $p1 = "ReleaseV2.1&*"     ascii wide
        $f1 = "Installer_x64.exe" ascii wide
        $z1 = "setup.zip"         ascii wide
        $s1 = "7za"               ascii wide
        $k1 = "Latest Release_v2.1" ascii wide
        $e1 = "irm"               ascii wide
        $e2 = "| iex"             ascii wide
    condition:
        // strong unique strings, or the download+in-memory-exec idiom
        ($u1 and $p1) or ($f1 and $z1 and $s1 and $k1) or ($u1 and $e1 and $e2)
}
