Option Explicit

Const ADS_SCOPE_SUBTREE = 2

'' this will need changed based on site to query
Const LDAP_PATH = "LDAP://OU=Atlanta,DC=innotrac,DC=com"


Dim objConnection, objCommand, objRecordSet, objFSO, objTextFile

Set objFSO = CreateObject("Scripting.FileSystemObject")
Set objTextFile = objFSO.CreateTextFile("os.tsv", True)

'' create object and connection to AD
Set objConnection = CreateObject("ADODB.Connection")
Set objCommand =   CreateObject("ADODB.Command")
objConnection.Provider = "ADsDSOObject"
objConnection.Open "Active Directory Provider"



Set objCOmmand.ActiveConnection = objConnection
'' what do we want
objCommand.CommandText = _
    "Select Name, operatingSystem, operatingSystemServicePack, operatingSystemVersion, distinguishedName from '" & LDAP_PATH & "' Where objectClass='computer'"  
objCommand.Properties("Page Size") = 1000
objCommand.Properties("Searchscope") = ADS_SCOPE_SUBTREE 
Set objRecordSet = objCommand.Execute
objRecordSet.MoveFirst

'' write helper date info
objTextFile.WriteLine "LDAP Path: " & LDAP_PATH
objTextFile.WriteLine "Run Date & Time" & Date & " " & Time

'' write header in output file
objTextFile.WriteLine "Computer Name" & vbTab & "OS" & vbTab & "OS Version" & vbTab & "OS SP" & vbTab & "DN"

'' loop through writing out data
Do Until objRecordSet.EOF
	objTextFile.WriteLine objRecordSet.Fields("Name").Value & _
    	vbTab & objRecordSet.Fields("operatingSystem").Value & _
    	vbTab & objRecordSet.Fields("operatingSystemVersion").Value & _
    	vbTab & objRecordSet.Fields("operatingSystemServicePack").Value & _
    	vbTab & objRecordSet.Fields("distinguishedName").Value
    If InStr(1, LCase(objRecordSet.Fields("operatingSystem").value), "server", 1) = 0 Then ''search for the string `server` in the OS field and skip listing software if found 
    	ListSoftwareInstalled objRecordSet.Fields("Name").Value ''call our helper function to collect installed software before we move on
    End If
    objRecordSet.MoveNext
Loop

Function ListSoftwareInstalled(strPC)
	Dim objWMIService, colSoftware, objS, strTmp
	strTmp = "" 'clear out string holder
	Set objWMIService = GetObject("winmgmts:{impersonationLevel=impersonate}!\\" & strPC & "\root\cimv2")
	Set colSoftware = objWMIService.execquery("SELECT * FROM Win32_Products")
	For Each objS In colSoftware
		objTextFile.WriteLine "  " & objS.caption & vbTab & objS.description & vbTab & objS.name & objS.version
	Next
End Function 