Option Explicit

Dim shell, projectDir, launcher, browserUrl, edge, chrome
Set shell = CreateObject("WScript.Shell")
projectDir = CreateObject("Scripting.FileSystemObject").GetParentFolderName(WScript.ScriptFullName)
launcher = projectDir & "\start_app.bat"
browserUrl = "http://127.0.0.1:5003"

shell.CurrentDirectory = projectDir
shell.Run Chr(34) & launcher & Chr(34), 0, False
WScript.Sleep 5000

edge = shell.ExpandEnvironmentStrings("%ProgramFiles(x86)%") & "\Microsoft\Edge\Application\msedge.exe"
chrome = shell.ExpandEnvironmentStrings("%ProgramFiles%") & "\Google\Chrome\Application\chrome.exe"
If CreateObject("Scripting.FileSystemObject").FileExists(edge) Then
	shell.Run Chr(34) & edge & Chr(34) & " --new-window " & browserUrl, 1, False
ElseIf CreateObject("Scripting.FileSystemObject").FileExists(chrome) Then
	shell.Run Chr(34) & chrome & Chr(34) & " --new-window " & browserUrl, 1, False
Else
	shell.Run browserUrl, 1, False
End If
