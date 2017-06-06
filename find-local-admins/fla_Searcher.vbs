
Option Explicit
On Error Resume Next

''******************************************************************************
''    A script to scan network computers to find out which users have 
''    local admin rights.
''
'' Mods by Todd Fencl 7:53 AM 10/5/2009
''  - modify line that if UserName not `Domain Admin` or `Administrator` we 
''    denote the line a little more with ` <----- Review`
''
'' Mods by Todd Fencl 07:02 am 1/12/2009
''  - rename all I/O to fla_??
''  - wrote routines to search AD for all computers and output to list
''
'' 10:45 AM Thursday, April 16, 2009
''  - purge old file first, then create new computer_names file
''  - trap and log if computer_names file does not exist, record error in
''    results file.
''
'' 9:33 AM Monday, June 15, 2009
''  - add email function to email output file to ColumbusHelpDesk
''
'' 12/17/2012 0815
''  - modified for running in John's Creek office and tweaks to output if 
''    computer not found
''******************************************************************************

''=====DEFINE VARIABLES=========================================================

''vvvvv ONLY LINE THAT SHOULD NEED CHANGED IS THE NEXT LINE vvvvv
Const gstrLDAP = "LDAP://OU=GAJC,OU=Georgia,DC=Innotrac,DC=com" 'this is WHERE you want to look for computer objects

Const ForWriting = 2

'' 2009.06.15 for email
Const strSMTPServer = "gaslexc10"					'MAIL SERVER NAME
Const strFrom = "ohsvc@innotrac.com"				'FROM FIELD
'Const strTo = "TSSAlerts-Ohio@innotrac.com"		'TO FIELD
Const strTo = "tfencl@innotrac.com"					'TO FIELD - test
Const strSubject = "Found Local Admins Report"		'SUBJECT LINE
Const cdoUserName = "xxx"							'IF AUTHENTICATION NEEDED
Const cdoPassword = "xxx"							'IF AUTHENTICATION NEEDED

Const fltVersion = "2.1"
Const cdoAnonymous = 0 'no authentication needed
Const cdoBasic = 1  'clear-text authentication
Const cdoNTLM = 2  'NTLM authentication


Dim objFSO, objResults, objFileIn, objGroup, objUser
Dim strComputer, strAppPath
''=====DEFINE VARIABLES=========================================================
strComputer = ""

''******************************************************************************
''Creates my results log file, overwriting the old file if one exists.
''******************************************************************************
strAppPath = InStr(1, WScript.ScriptFullName, WScript.ScriptName)
strAppPath = Left(WScript.ScriptFullName, strAppPath - 1)

Set objFSO = CreateObject("Scripting.FileSystemObject")
Set objResults = objFSO.CreateTextFile(strAppPath & "fla_Results.txt", ForWriting)

objResults.WriteLine "------|| Start Time: " & Now() & " ||------"
objResults.WriteBlankLines(1)
objResults.WriteLine "To remove users on remote computers we can use the following commands: "
objResults.WriteLine "  psexec \\<remote_computer>  net localgroup Administrators <local_user_name> /del"
objResults.WriteLine "Report Queried for: " & gstrLDAP
objResults.WriteBlankLines(1)
objResults.WriteLine "***************************************************"
objResults.WriteLine "       User Accounts With Local Admin rights       "
objResults.WriteLine "***************************************************"


''=====
''excuse me, we need to slip away for a minute and make a phone call, our 
''friend will make a list of computers read from AD so we are current and 
''have good updated list.
''
''--sometime people forget to update the input--
''
''=====
Call BuildComputerList()

'WScript.Echo "back from BuildComputerList()"


''******************************************************************************
''Opens and reads the fla_computer_names.txt file containing a list
''of computers to be scanned.
''******************************************************************************
Set objFSO = CreateObject("Scripting.FileSystemObject")
If objFSO.FileExists(strAppPath & "fla_computer_names.txt") Then
	Set objFileIn = objFSO.OpenTextFile(strAppPath & "fla_computer_names.txt")
	'WScript.Echo "found list of computer names"
Else
    'Wscript.Echo "The fla_computer_names.txt file does not exist."
	objResults.WriteBlankLines(2)
	objResults.WriteLine "***********************************************************"
	objResults.WriteLine "*** Critical error: missing fla_computer_names.txt file ***"
	objResults.WriteLine "***********************************************************"
	WScript.Quit()
End If

Do Until objFileIn.AtEndOfStream
	''***************************************************************************
	''This line clears the User account variable so offline and non-existent
	''computers return a null value.
	''***************************************************************************
	objGroup = ""
	If objFileIn.AtEndOfStream = False Then
		strComputer = objFileIn.ReadLine
		'WScript.Echo "pc name: " & strComputer '(Use for testing only!!!)
		''**********************************************************************
		''Finds all user accounts on each computer that have local admin rights.
		''**********************************************************************
		Set objGroup = GetObject("WinNT://" & strComputer & "/Administrators")
		
		''Check to see if an error was raised in the connection to the remote pc. If
		''the error was "Network path cannot be found - 80070035" then simply move
		''on as the pc is not online / not found. If not, then write some info out
		''so we know what happened ... 
		
		If Err.Number > 0 Then 
			objResults.WriteLine "##### Error " & String(33, "#") & vbCrLf &_
			"Could not connect to " & strComputer & vbCrLf & _
			"Error:" & vbTab & Err.Number & " -- " & Err.Description & vbCrLf & _
			"Src:" & vbTab & Err.Source & vbCrLf & _
			String(45, "#")
			
		''just could not connect to the pc, note the name in case we want to clean up ...
'		Else If Err.Number = -2147024843 Then '80070035 - The network path cannot be found
'			objResults.WriteLine "Cound not connect / find " & strComputer
		
		''We successfully connected to the remote computer now search it ...
		Else
			objResults.WriteLine String(60, "*")
			objResults.WriteBlankLines(1)
			objResults.WriteLine "Computer: \\" & strComputer
			'objResults.WriteBlankLines(1)
			objResults.WriteLine "Local Admins:"
			objResults.WriteLine String(15, "-")
			For Each objUser In objGroup.Members
				'WScript.Echo "admin: " & objUser.Name '(Use for testing only!!!)
				''make everything lower case for testing purposes.
				If Not ((LCase(objUser.Name) = "administrator") Or (LCase(objUser.Name) = "domain admins")) Then
					objResults.WriteLine vbTab & objUser.Name & vbTab & vbTab & " <---- Review"
				Else
					objResults.WriteLine vbTab & objUser.Name
				End If
				objResults.WriteBlankLines (1)
				objResults.WriteLine String(60, "*")
			Next

		End If 'end err.number (could not connect to pc)
	End If
Loop

objFileIn.Close
objResults.WriteLine "------|| End  Time: " & Now() & " ||------"
objResults.Close

Call SendMail()

'WScript.Echo "The script has finally finished running!" & Now()
WScript.Quit()

''==============================================================================
'' Functions, we all know 'em, we all love 'em ...
''==============================================================================
Function BuildComputerList()
	''variables needed so we can talk to AD and query for computer objects
	Dim objConnection, objCommand, objFileOut, objRecordSet
	Dim strOutPut

	Const ADS_SCOPE_SUBTREE = 2

	Set objConnection = CreateObject("ADODB.Connection")
	Set objCommand = CreateObject("ADODB.Command")
	objConnection.Provider = "ADSDSOObject"
	objConnection.Open "Active Directory Provider"
	
	''this is the file that we will list computer names to, read later as input
	''strScriptPath = Replace(wscript.scriptfullname, wscript.scriptname, "")
	strOutPut =  strAppPath & "\fla_computer_names.txt"
	
	''delete the old file if it exists
	If objFSO.FileExists(strOutPut) Then
		objFSO.DeleteFile(strOutPut)
	End If

	''create the file for output
	Set objFileOut = objFSO.CreateTextFile(strOutPut, ForWriting)
	
	''connect to AD settings some params
	Set objCommand.ActiveConnection = objConnection
	objCommand.Properties("Page Size") = 1000
	objCommand.Properties("Searchscope") = ADS_SCOPE_SUBTREE
	objCommand.Properties("Cache Results") = False
	''like SQL, the statement that we are looking for
	''there are lots of things we can get, but all we need is the CN field
	objCommand.CommandText = "Select cn from '" & gstrLDAP &  "' Where objectClass='computer'"  
	Set objRecordSet = objCommand.Execute
	''we are probably at the end of the dataset, go back to start (just don't pass Go)
	objRecordSet.MoveFirst
	Do Until objRecordSet.EOF 
		objFileOut.WriteLine objRecordSet.Fields("CN").Value
'		WScript.Echo objRecordSet.Fields("CN").Value
		objRecordSet.MoveNext
	Loop
	
	''now that we've looped through all the returned computers, we can clean up
	''and exit
	objFileOut.Close
End Function 'end BuildComputerList

Function SendMail()
	''***** START SEND MAIL LOGIC *****
	Dim objEmail, objMail
	Set objEmail = CreateObject("CDO.Message")
	Set objMail = CreateObject("CDO.Message")
	objMail.Configuration.Fields.Item ("http://schemas.microsoft.com/cdo/configuration/sendusing") = 2
	objMail.Configuration.Fields.Item ("http://schemas.microsoft.com/cdo/configuration/smtpserver") = strSMTPServer
	objMail.Configuration.Fields.Item ("http://schemas.microsoft.com/cdo/configuration/smtpserverport") = 25
	objMail.Configuration.Fields.Item ("http://schemas.microsoft.com/cdo/configuration/smtpauthenticate") = cdoAnonymous
	''******************************************************************************
	''***** IF MAIL FAILES, YOU MIGHT NEED TO AUTHENTICATE TO THE MAIL SERVER, TRY cdoBasic FIRST
	''***** IF YOU DON'T NEED TO AUTHENTICATE, REMARK THE NEXT 2 LINES OUT
	''******************************************************************************
	'objMail.Configuration.Fields.Item ("http://schemas.microsoft.com/cdo/configuration/sendusername") = cdoUserName
	'objMail.Configuration.Fields.Item ("http://schemas.microsoft.com/cdo/configuration/sendpassword") = cdoPassword
	''
	''Actual body of the message. I know, a lot of work just to send a message but hey, what are you going to do! :-)
	objMail.From = strFrom
	objMail.To = strTo
	objMail.Subject = strSubject
	objMail.TextBody = "We ran the Find Local Administrators script. Attached is the output file for review." & _
		vbCrLf & _
		vbCrLf & _
		"Thank you," & vbCrLf & _
		"Mr. Roboto" & vbCrLf & _
		"version: " & fltVersion
	objMail.AddAttachment strAppPath & "\fla_Results.txt" 'need to pass the entire path, and i don't like D:\xxx\xxx :{
	objMail.Configuration.Fields.Update
	objMail.Send
End Function 'end SendMail