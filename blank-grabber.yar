rule blankgrabber {
  meta:
    author = "Jesus Papita"
    filetype = "Python exe64"
    version = "1.0"
  strings:
    $python_string = "python" nocase ascii wide
    $pyinstaller_string = "pyinstaller" nocase ascii wide
    $crypto_dll1 = "blibssl-3.dll" nocase ascii wide
    $python_dll = "python314.dll" nocase ascii wide
    $wmi_string = "b_wmi.pyd" nocase ascii wide
    $aes_file = "blank.aes" nocase ascii wide
    $winrar_string = "rar.exe" nocase ascii wide
    $rarkey_string = "rarreg.key" nocase ascii wide
    $hex1 = {00 00 00 00 00 00 00 00 04 00 00 00 00 00 ?? 00}
  condition:
    (uint16(0) == 0x5A4D /*EXE magic byte in big endian*/ and $python_string and $pyinstaller_string and $wmi_string and $winrar_string and $rarkey_string and $hex1) and ($aes_file or $python_dll or $crypto_dll1 or $hex1) 
}