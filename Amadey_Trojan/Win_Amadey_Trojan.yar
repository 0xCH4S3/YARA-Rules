import "pe"

rule Win_Amadey_Trojan {

    meta:
        author = "Gabriel Toledo - 0xCH4S3"
		date = "14/03/2025"
        
    strings:
        $id_1 = "Amadey" 
        $id_2 = {8B 45 08 89 04 24 E8 ?? ?? 00 00 39 45 F4 73 40 8B 75 F4 81 C6 ?? ?? 40 00 8B 45 08 8B 5D F4 01 C3 C7 04 24 00 50 40 00 E8 ?? ?? 00 00 89 C2 8B 45 F4 89 D1 BA 00 00 00 00 F7 F1 0F B6 92 00 50 40 00 0F B6 03 28 D0 88 06 8D 45 F4 FF 00 EB B0}
        
        $s_1 = "_Z10aBypassUACv" ascii
        $s_2 = "_Z11aCheckAdminv" ascii
        $s_3 = "_Z11aRunAsAdminPc" ascii
        $s_4 = "_Z15aUrlMonDownloadPcS_" ascii
        $s_5 = "_Z16aExtractFileNamePc" ascii
        $s_6 = "_Z19aGetSelfDestinationi" ascii
        $s_7 = "_Z11aAutoRunSetPc" ascii
        $s_8 = "_Z13aGetProcessILv" ascii
        $s_9 = "_Z9aCopyFilePcS_" ascii
        $s_10 = "_Z13aDropToSystemPc" ascii
        $s_11 = "_Z7aPathAVPc" ascii

    condition:
        uint16(0) == 0x5A4D 
		and all of ($id_*) and 5 of ($s_*) and filesize < 100KB
}