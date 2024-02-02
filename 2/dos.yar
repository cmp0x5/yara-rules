rule dos {
	meta:
		description = "dos test"
		date = "2024-02-01"
		DaysOfYARA = "2/100"
	strings:
		$s1 = { 54 68 69 73 20 70 72 6f 67 72 61 6d 20 63 61 6e 6e 6f 74 20 62 65 20 72 75 6e 20 69 6e } 
		$s2 = "This program cannot be run in"
	condition:
		uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550 and all of ($s*) /* DOS header magic at 0x00 (WORD, 16 bit) and DWORD e_lfanew pointer at 0x3c towards DWORD signature in _IMAGE_NT_HEADERS */
}