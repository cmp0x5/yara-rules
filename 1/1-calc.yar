rule calc {
	meta:
        description = "testing yara rule for calc.exe" 
		date = "2023-01-31"
		DaysOfYARA = "1/100"
		SHA256Hash = "58189cbd4e6dc0c7d8e66b6a6f75652fc9f4afc7ce0eba7d67d8c3feb0d5381f"
	strings:
		$s1 = "CalculatorWinMain" ascii wide
		$s2 = "MicrosoftCalculator" ascii wide
	condition:
		all of ($s*)

}
		
		