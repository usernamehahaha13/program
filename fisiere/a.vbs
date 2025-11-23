Set WshShell = CreateObject("WScript.Shell")
Set WshNetwork = CreateObject("WScript.Network")


' Random string generation function
Function RandomString(length)
    Dim chars, str, i
    chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    str = ""
    For i = 1 To length
        str = str & Mid(chars, Int((Len(chars) * Rnd) + 1), 1)
    Next
    RandomString = str
End Function

' Generate random XXXXX-XXXXX format values
Randomize
Dim csName, primaryOwnerName
csName = RandomString(5) & "-" & RandomString(5)
primaryOwnerName = RandomString(5) & "-" & RandomString(5)

' Modify registry values for computer name and owner
Set objShell = CreateObject("WScript.Shell")
objShell.RegWrite "HKLM\SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName\ComputerName", csName, "REG_SZ"
objShell.RegWrite "HKLM\SYSTEM\CurrentControlSet\Control\ComputerName\ActiveComputerName", csName, "REG_SZ"


' Clean up objects
Set WshShell = Nothing
Set WshNetwork = Nothing
Set objShell = Nothing
Set fso = Nothing
