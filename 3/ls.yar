rule ls_1_Feb5 {
    meta:
        description = "simple ls, dir, dirv detection rule"
		DaysOfYARA = "3/100"
		date = "2024-02-05"
    strings:
        $s1 = "Richard M. Stallman"
        $s2 = "group-directories-first"
        $s3 = "inode"
        $s4 = "David MacKenzie"
        $s5 = "A NULL argv[0] was passed through an exec system call.\n"
        $s6 = "if OK,\n"
        $s7 = "if minor problems (e.g., cannot access subdirectory),\n"
        $s8 = "if serious trouble (e.g., cannot access command-line argument).\n"
    condition:
        ( uint16(0) == 0x457f and filesize < 150KB and all of them )
}
