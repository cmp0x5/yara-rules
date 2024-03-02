rule testxor {
	meta:
		description = "xor test"
		date = "2024-02-01"
		DaysOfYARA = "2/100"
	strings:
		$s1 = "https://camposvictor.com" xor(0x01-0xff)
		$s2 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" xor(0x01-0xff)
	condition:
		$s1 and $s2
}