' JVHD-nocmd.vbs - chay JVHD.bat voi cua so CMD an hoan toan
Set WshShell = CreateObject("WScript.Shell")
WshShell.CurrentDirectory = "D:\Android App\JVHD"
WshShell.Run """" & "D:\Android App\JVHD\JVHD.bat" & """", 0, False