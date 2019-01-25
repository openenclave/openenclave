'Get command-line arguments.
Set parameters = WScript.Arguments
Set FS = CreateObject("Scripting.FileSystemObject")
SourceDir = FS.GetAbsolutePathName(parameters(0))
ZipFile = FS.GetAbsolutePathName(parameters(1))

'Create empty ZIP file.
CreateObject("Scripting.FileSystemObject").CreateTextFile(ZipFile, True).Write "PK" & Chr(5) & Chr(6) & String(18, vbNullChar)

Set shell = CreateObject("Shell.Application")

Set source_objects = shell.NameSpace(SourceDir).Items
Set ZipDest = shell.NameSpace(ZipFile)
Count=ZipDest.Items().Count
shell.NameSpace(ZipFile).CopyHere(source_objects)

'Required to let the zip command execute
Do While Count = ZipDest.Items().Count
    wScript.Sleep 200
Loop
