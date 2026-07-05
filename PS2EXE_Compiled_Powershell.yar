import "pe"

rule PS2EXE_Compiled_PowerShell
{
    meta:
        description = "Detects PowerShell scripts compiled to EXE via PS2EXE (Invoke-ps2exe)"
        author = "Shreethaar"
        reference = "https://github.com/MScholtes/PS2EXE"
        reference2 = "mandiant/capa-rules PR #1168"
        date = "2026-07-05"
        // Detects the WRAPPER, not the embedded payload. A modified PS2EXE
        // build that renames its classes / mangled help text will evade this.

    strings:
        // --- Core PS2EXE class-name artifacts (main detection anchor) ---
        $class1 = "PS2EXEApp" ascii wide
        $class2 = "PS2EXE_Host" ascii wide
        $class3 = "PS2EXEHostUI" ascii wide
        $class4 = "PS2EXEHostRawUI" ascii wide

        // --- The 'zz'-mangled help text: PS2EXE substitutes e -> zz in its
        //     own -extract help string. Highly specific, near-zero FP. ---
        $help1 = "zzxtract" ascii wide
        $help2 = "spzzcify thzz" ascii wide
        $help3 = "filzznamzz" ascii wide

        // --- In-process PowerShell hosting APIs the wrapper compiles in ---
        $api1 = "System.Management.Automation" ascii wide
        $api2 = "GetManifestResourceStream" ascii wide
        $api3 = "RunspaceFactory" ascii wide

    condition:
        // Must be a .NET PE (managed wrapper); cheap gate first
        uint16(0) == 0x5A4D and
        pe.imports("mscoree.dll") and

        (
            // Path A: explicit PS2EXE class strings — strongest signal
            2 of ($class*)

            // Path B: the self-obfuscated help text — the capa #1168 branch
            or 2 of ($help*)

            // Path C: no class strings (stripped build) but the full
            //         in-process-hosting API triad — catches renamed variants
            or all of ($api*)
        )
}
