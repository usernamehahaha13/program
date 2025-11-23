Set WshShell = CreateObject("WScript.Shell")
Set WshNetwork = CreateObject("WScript.Network")

' Bilgi mesajı göster
MsgBox "OK TUSUNA BAS", vbInformation + vbOKOnly, "DONE"

' Bilgisayarı yeniden başlat
WshShell.Run "shutdown /r /t 5", 0, False

' Belleği temizle
Set WshShell = Nothing
Set WshNetwork = Nothing
Set fso = Nothing
