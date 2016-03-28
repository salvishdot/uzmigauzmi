#Include <File.au3>

_DirRemoveContents(@UserProfileDir & '\Downloads')

Func _DirRemoveContents($folder)
    Local $list_of_contents, $status
    $list_of_contents = _FileListToArray($folder)
    If IsArray($list_of_contents) Then
        If StringRight($folder, 1) <> "\"  Then $folder = $folder & "\" 
        If @error = 1 Then Return 1 ; No Files\Folders Found
        For $a = 1 To $list_of_contents[0]
            FileSetAttrib($folder & "\" & $list_of_contents[$a], "-RASH")
            If StringInStr(FileGetAttrib($folder & $list_of_contents[$a]), "D") Then
                $status = DirRemove($folder & $list_of_contents[$a], 1)
            Else
                $status = FileDelete($folder & $list_of_contents[$a])
            EndIf
        Next
    Else
        Return 2 ; Directory doesn't exists
    EndIf
EndFunc   ;==>_DirRemoveContents