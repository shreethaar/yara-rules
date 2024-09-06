rule CobaltStrike_Payload {
    meta:
        description = "Detects Cobalt Strike payloads"
        author = "YourName"
        date = "2024-09-06"
        version = "1.0"

    strings:
        $s1 = "ReflectiveLoader" ascii
        $s2 = "beacon" ascii
        $s3 = "malleable_profile" ascii
        $s4 = "ProcessInject" ascii
        $s5 = "Exitfunk" ascii
        $s6 = "StageWrite" ascii

    condition:
        uint16(0) == 0x5A4D and // Checks for 'MZ' header indicating a PE file
        any of ($s*)
}

