rule MAL_Mimikatz_WIN_EXE_Sept7
{
		meta: 
		description = "Detects the Mimikatz executable using a hardcoded URL string"
		author = "Shreethaar"
		date = "2024-09-07"
		reference = "https://example.com/malware12"
		tags = "malware, windows, lsass"
		hash = "92804faaab2175dc501d73e814663058c78c0a042675a8937266357bcfb96c50"
		id = "12345"
		version = "1.0"

		strings:
		$url = "http://blog.gentilkiwi.com/mimikatz" ascii
		//$PE_signature = "MZ"
		$PE_signature = { 4D 5A } //MZ in hexadecimal
		
		condition:
		$PE_signature at 0 and 
		$url
}

