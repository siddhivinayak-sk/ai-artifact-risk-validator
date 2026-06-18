/*
 * YARA rules for detecting hack tool and exploit framework indicators.
 * Risk ID: Y-S4 (Hack Tool / Exploit Match)
 */

rule HackTool_ReverseShellPython {
    meta:
        description = "Python reverse shell stager pattern"
        severity = "HIGH"
        risk_id = "Y-S4"
    strings:
        $socket_import = "import socket" ascii
        $subprocess_import = "import subprocess" ascii
        $connect = ".connect((" ascii
        $bash_i = "bash -i" ascii nocase
        $sh_i = "/bin/sh" ascii
        $dup2 = "os.dup2(" ascii
    condition:
        $socket_import and ($subprocess_import or $dup2) and ($connect or $bash_i or $sh_i)
}

rule HackTool_MSFPayload {
    meta:
        description = "Metasploit payload indicator"
        severity = "HIGH"
        risk_id = "Y-S4"
    strings:
        $msf1 = "msfvenom" ascii nocase
        $msf2 = "meterpreter" ascii nocase
        $msf3 = "payload/python/meterpreter" ascii nocase
        $msf4 = "LHOST=" ascii
        $msf5 = "LPORT=" ascii
    condition:
        2 of them
}

rule HackTool_PowerShellDownloadExec {
    meta:
        description = "PowerShell download-and-execute pattern"
        severity = "HIGH"
        risk_id = "Y-S4"
    strings:
        $iex1 = "IEX(" ascii nocase
        $iex2 = "Invoke-Expression" ascii nocase
        $dl1 = "DownloadString(" ascii nocase
        $dl2 = "Net.WebClient" ascii nocase
        $dl3 = "Invoke-WebRequest" ascii nocase
    condition:
        ($iex1 or $iex2) and ($dl1 or $dl2 or $dl3)
}

rule HackTool_SQLMapIndicator {
    meta:
        description = "SQLMap SQL injection tool signature"
        severity = "HIGH"
        risk_id = "Y-S4"
    strings:
        $sqlmap1 = "sqlmap" ascii nocase
        $sqlmap2 = "--dump-all" ascii
        $sqlmap3 = "--sql-shell" ascii
        $sqlmap4 = "--os-shell" ascii
    condition:
        $sqlmap1 and ($sqlmap2 or $sqlmap3 or $sqlmap4)
}
