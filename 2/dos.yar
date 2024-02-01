rule dos {
	meta:
		description = "dos test"
		date = "2024-02-01"
		DaysOfYARA = "2/100"
	strings:
		$s1 = { 54 68 69 73 20 70 72 6f 67 72 61 6d 20 63 61 6e 6e 6f 74 20 62 65 20 72 75 6e 20 69 6e } 
		$s2 = "This program cannot be run in"
		$h1 = { 4d 5a }
	condition:
		all of them
		
}