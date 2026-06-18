/*
 * YARA rules for detecting webshell patterns in AI artifact scripts.
 * Risk ID: Y-S2 (Webshell Match)
 *
 * These signatures target common PHP, Python, and generic webshell indicators
 * that could be bundled as executable scripts within AI skill packages.
 */

rule PythonWebshell_OSCommandExec {
    meta:
        description = "Python script with webshell-style OS command execution via HTTP parameters"
        severity = "CRITICAL"
        risk_id = "Y-S2"
    strings:
        $cgi1 = "cgi.FieldStorage" ascii
        $cgi2 = "os.popen" ascii
        $cgi3 = "subprocess.Popen" ascii
        $http1 = "environ.get" ascii
        $http2 = "QUERY_STRING" ascii
        $exec1 = "os.system" ascii
    condition:
        ($cgi1 or $http1 or $http2) and ($exec1 or $cgi2 or $cgi3)
}

rule PHPWebshell_EvalBase64 {
    meta:
        description = "PHP webshell using eval+base64_decode pattern"
        severity = "CRITICAL"
        risk_id = "Y-S2"
    strings:
        $php_tag = "<?php" ascii nocase
        $eval = "eval(" ascii nocase
        $b64 = "base64_decode(" ascii nocase
        $post = "$_POST" ascii
        $get  = "$_GET" ascii
        $req  = "$_REQUEST" ascii
    condition:
        $php_tag and $eval and $b64 and ($post or $get or $req)
}

rule GenericWebshell_SystemCommand {
    meta:
        description = "Script executing system commands from HTTP request parameters"
        severity = "CRITICAL"
        risk_id = "Y-S2"
    strings:
        $cmd1 = "passthru(" ascii nocase
        $cmd2 = "shell_exec(" ascii nocase
        $cmd3 = "system(" ascii nocase
        $cmd4 = "popen(" ascii nocase
        $input1 = "$_GET[" ascii
        $input2 = "$_POST[" ascii
        $input3 = "request.args" ascii
        $input4 = "request.form" ascii
    condition:
        ($cmd1 or $cmd2 or $cmd3 or $cmd4) and ($input1 or $input2 or $input3 or $input4)
}
