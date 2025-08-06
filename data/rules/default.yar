
rule Suspicious_Executable {
    meta:
        description = "Detects suspicious executable patterns"
        severity = "medium"
    
    strings:
        $s1 = "CreateRemoteThread" ascii
        $s2 = "VirtualAllocEx" ascii
        $s3 = "WriteProcessMemory" ascii
        $s4 = "SetWindowsHookEx" ascii
    
    condition:
        2 of ($s*)
}

rule Potential_Keylogger {
    meta:
        description = "Detects potential keylogger behavior"
        severity = "high"
    
    strings:
        $k1 = "GetAsyncKeyState" ascii
        $k2 = "SetWindowsHookEx" ascii
        $k3 = "WH_KEYBOARD" ascii
        $k4 = "keylog" ascii nocase
    
    condition:
        2 of ($k*)
}

rule Suspicious_PowerShell {
    meta:
        description = "Detects suspicious PowerShell commands"
        severity = "medium"
    
    strings:
        $p1 = "powershell" nocase
        $p2 = "-enc" nocase
        $p3 = "-nop" nocase
        $p4 = "-w hidden" nocase
        $p5 = "IEX" nocase
        $p6 = "DownloadString" nocase
    
    condition:
        $p1 and 2 of ($p2, $p3, $p4, $p5, $p6)
}
