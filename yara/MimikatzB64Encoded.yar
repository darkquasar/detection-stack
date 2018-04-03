rule MimikatzB64Encoded
{
    meta:			
        author = "@DarkQuasar"
        description = "This rule identifies x64 B64 encoded instances of Mimikatz based on the Yara rule that detects Mimikatz per its Byte Strings" threat_level = 10 score = 100

	strings:
    	$b64x64Hex_01 = { 6B 33 ?? ?? 76 7A 52 59 58 ?? 64 41 } /* HEX version of ASCII B64 "k3 ?? ?? vzRYX ?? dA" */
              
    condition:
        $b64x64Hex_01
}
