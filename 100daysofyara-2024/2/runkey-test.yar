rule runkey {
	meta:
		description = "runkey test"
		date = "2024-02-01"
		DaysOfYARA = "2/100"
	strings:
		$s1 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii wide
		$s2 = { 53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e }
	condition:
		any of ($s*)
		