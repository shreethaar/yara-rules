rule RuntimeComponents_Electron_JS_Dropper
{
    meta:
        description = "Electron main.js dropper w/ Telegram C2 (Runtime Components lure)"
        date        = "2026-07-04"
    strings:
        $cfg1 = "Runtime Components" ascii wide
        $ip1  = "62.60.226.198"      ascii
        $url1 = "/uploads/5df66d1d1d5343828aea45cea2b76c5c.exe" ascii
        $tg1  = "api.telegram.org"   ascii wide
        $tg2  = "sendMessage"        ascii wide
        $tg3  = "sendPhoto"          ascii wide
        $dd1  = "net_"               ascii wide          // dedup marker prefix
        $dfn1 = "Exclusions"         ascii wide          // Defender exclusion writes
        $cache = "Setup\\cache"      ascii wide
    condition:
        ($cfg1 and $ip1) or
        ($url1) or
        ($tg1 and ($tg2 or $tg3) and ($dfn1 or $cache or $dd1))
}
