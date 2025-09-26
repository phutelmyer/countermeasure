/*
Sample YARA rules for testing
*/

rule SuspiciousPEFile
{
    meta:
        description = "Detects suspicious PE file characteristics"
        author = "Test Security Team"
        date = "2024-01-01"
        version = "1.0"
        reference = "https://example.com/analysis"

    strings:
        $pe_header = { 4D 5A }
        $suspicious_api1 = "VirtualAlloc" ascii
        $suspicious_api2 = "WriteProcessMemory" ascii
        $suspicious_api3 = "CreateRemoteThread" ascii
        $packer_string = "UPX" ascii

    condition:
        $pe_header at 0 and
        (2 of ($suspicious_api*) or $packer_string)
}

rule PowerShellEmpire
{
    meta:
        description = "Detects PowerShell Empire framework artifacts"
        author = "Test Security Team"
        date = "2024-01-01"
        version = "1.0"
        reference = "https://attack.mitre.org/software/S0363/"

    strings:
        $empire_agent = "emp_" ascii
        $empire_function1 = "Get-Empire" ascii wide
        $empire_function2 = "Invoke-Empire" ascii wide
        $empire_staging = "staging_key" ascii
        $http_default_response = "default response" ascii

    condition:
        any of them
}

rule CobaltStrikeBeacon
{
    meta:
        description = "Detects Cobalt Strike Beacon payloads"
        author = "Test Security Team"
        date = "2024-01-01"
        version = "1.0"
        reference = "https://attack.mitre.org/software/S0154/"

    strings:
        $beacon_config = { 00 01 00 01 00 02 }
        $beacon_metadata = "BEACON" ascii
        $malleable_c2 = "ConstHeaders" ascii
        $pipe_name = "\\\\.\\pipe\\msagent_" ascii

    condition:
        any of them
}

rule Mimikatz
{
    meta:
        description = "Detects Mimikatz credential dumping tool"
        author = "Test Security Team"
        date = "2024-01-01"
        version = "1.0"
        reference = "https://attack.mitre.org/software/S0002/"

    strings:
        $string1 = "sekurlsa::logonpasswords" ascii wide nocase
        $string2 = "privilege::debug" ascii wide nocase
        $string3 = "crypto::capi" ascii wide nocase
        $string4 = "lsadump::sam" ascii wide nocase
        $string5 = "Benjamin DELPY" ascii wide
        $string6 = "gentilkiwi" ascii wide

    condition:
        2 of them
}