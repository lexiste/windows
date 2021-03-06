Option Explicit

''=================================================================================================================================
''
'' Active Directory User Management script [ADUM]
''
'' Written: 2011/07/18
'' Updated: 2015.07.21
'' Author: Todd Fencl [tfencl@innotrac.com]
'' Mod Author: Todd Fencl
''
'' Description: This script is part a wrapper, and part functional. The wrapper portion builds a parameter string for the 
''  application TrueLastLogon (TLL), which needs can be copied over to a share -or- installed, then calls the program and waits 
''  patiently for several minutes. The TLL program does not terminate when it completes, so we have to sleep for a long time span
''  then search for the running program and terminate it. Once this is done, we take that output file from TLL and use this as an
''  input for the rest of the script. 
'' 
''  We read in a list of exceptions that we do not want to disable based on either the exact user name, or a pattern like
''  matching routine, into an arry and then read line by line the TLL file that lists. We split the read in line, and fill a custom
''  user class array then call a routine to match up the currently active user and compare to the list of exception users. If there
''  is a match, then we log that the user should be disabled, but will not since there is a matching exception users. If the user
''  account is not matched, and the account status is Enabled, then we call a function to disable the account by setting the 
''  AccountDisabled to true and update the user object. This disables the account. We do not, in version 1.x, move the user to
''  a `Stale` OU, but leave the user where ever they currently are. 
''
''  Once all records have been processed we call a final function to generate and email message with information that we have 
''  completed running, and attach the debug file that lists actions on each user, wether it be disabling the account, skipping the
''  account due to an exception, etc. We also attache the original file generated by TLL.
''
'' As of 7/21/2011 I am waiting on getting my hands on a beta copy of TLL v3 that will have several new abilities, including the
''  ability to define additional AD properties so we can add .distinguishedName, .whenCreated and .whenChanged. The 
''  .distinguishedName will give us a big chunk of data that includes the entire LDAP string for the user object. This will allow
''  me to provide the exact location of the user for output; possibly allow us to determine whether we DISABLE or DELETE an account
''  based on the LDAP string.
''
'' Lines that start with '' (2x single quote) are comment lines where as lines with a single ' are commented out code lines for 
''  one reason or another. Debug lines, old lines that could possibly be removed, etc.
''
''
'' Known Issues:
''  07.18.11.0912 - when call truelastlogon with params, we can not get some of of columns back properly including the 
''   distinguishedName, whenCreated and whenChanged AD attributes
''
''  07.21.11.0724 - now that we are functional, I have set the cDisable to FALSE and we need TSS to review the results, update 
''   and additional exception users. Once we have a good exception list I'll need to generate a report file that we can review
''   with any BA types as client accounts may be impacted by this as well. 
''
''  07.25.11.0945 - change in the ConvertADName() to accept a boolean value to return either the LDAP string or the modified
''   string. This is because we dynamically create the string to pass to TrueLastLogon and need the LDAP string, but later on we 
''   need a modified string when we modify the user object with WinNT://.
''
''  08.09.11.0800 - there is an issue when using CDO.Message.AddAttachment that you MUST pass a fully qualified path for the file
''   to be attached. This appears to be due to a similiar issue as WScript.Path returning `C:\Windows\system32`, it is where the 
''   object is being created or executed.
''
'' Updates:
''  07.27.11.0700 - Adding a new file named strReportFile for output into CSV format of JUST the user data for a disabled account.
''   this will allow the Debug file to be just this, and the Report file to have data to send to the IT team. 
''
''   Creating new output file for just the information related to the disabled user object to a CSV file. This will have just the
''   disabled account information, and no debugging. We are still sending both files in email as attachments, but support does not
''   have to dig through the debug log information to find disabled accounts.
''
''  08.12.11.1510 - Added that when an account is disabled, we add a comment to the users .Description field with the following:
''   !ADUM Disabled: DDMonYYYY HH:MM
''  08.12.11.1530 - Added a check that if we do not find the exception list file we will log an error and quit. To many bad things
''   will happen without the exception file including, but not limited to breaking AD replication.
''
''  09.06.11.0820 - Changed the comment that is added to the user object .Description field. The original comment 
''   `!ADUM Disabled: 1September2011 9:8` was being truncated, it has been shortened to `!Disabled:2September2011 8:22` which 
''   should fit with any string.
''
''  01.04.2012.0845 - Changing some logic in executing the TrueLastLogon, the .Sleep timer calculations and added check for the 
''   existance of the strTLLFile after returning from calling TrueLastLogon.
''
''  02.06.2012.1600 - Still having problems running this on the servers. Rewriting some routines and logic to work on my desktop
''   with the newer version 3 and the new TrueLastLogonCLI application that provides greater flexibility. Added more detailed error
''   codes as well if we exit early.
''   9000 -- could not find the executable path cAppPath variable
''   9001 -- could not find the exception file in the cPath variable
''   9002 -- error in the system call to cTLLAPP
''   9003 -- could not find the output file strTLLFile from the TrueLastLogon external call
''
'' 09.04.2012.1130 - recent change in AD with GASLGCT02 being renamed to GANCGCT02 has caused issues with TrueLastLogon as 
''  GASLGCT02 is still showing as a Domain Controller but when attempts to query it TrueLastLogon fails with a "Local Error". With
''  the existing CountDCs() loop through and build a list of domain controllers, and exclude GASLGCT02 from a list. Then use this 
''  list for TrueLastLogonCLI /DC:server1,server2,server3 format.
''
'' 2013.04.09.1530 - rebuilt my desktop and using the opportunity to move stuff from my non-backed up desktop C drive to my mapped
''  H drive. Provides backups at least for now as we still can't manage to get the true last logon and vbs extensions to execute
''  properly on the servers. 
''
'' 2013.12.17.1315 - When the user account is disabled, and the .Description is added with the string, we need to read in the 
''  previous data in the .Description and then append the (!TPC <date>) data.
''
'' 2014.05.13.1545 - change cSMTPServer address from gaslexc10 to new smtpmail.innotrac.com after gaslexc10 was retired
''
'' 2014.10.08.0930 - added it_noc@innotrac.com email address to cTo string
''
'' 2014.12.01.1300 - re-enabled cDisable flag back to 1, disabled for some reason and no accounts were disabled on December run.
''
'' 2015.07.21:0930 - check added to the CountDCs functoin when the displayName of an object comes back empty the function Left would 
''  fail. Added IF..ELSE check to make sure there is a value. Emailed Windows Server admins as to why host object GAJCDC02 would not 
''  have the correct attributes (missing displayName).
''
'' 2015.08.03:1500 - Adjustments to logic in CountDCs and fix bug in checking length for host name after check was added on 7/21.
''
'' 2016.11.09:0930 - adjusted cSMTPServer from smtpmail.innotrac.com to mailhost.innotrac.com
''
''=================================================================================================================================

''### VARIABLES THAT MIGHT NEED TWEAKED ###
''Needed for sending email, To, CC, mail server
'Const cTo = ""
Const cTo = "tss@innotrac.com; ITunixsystems@innotrac.com, it_noc@innotrac.com"	'WHO ARE WE SENDING EMAIL TO
Const cCC = "tfencl@radial.com"				'WHO TO CC IF ANY
Const cSMTPServer = "mailhost.innotrac.com"	'EMAIL - EXCHANGE SERVER
Const cFrom = "helpdesk@innotrac.com"		'EMAIL - WHO FROM
Const cSubject = "Active Directory User Management report"	'EMAIL - SUBJECT LINE

''Most likely not needed, but if needed to pass authorization for connecting and sending emails
Const cdoUserName = "account@domain.com"	'EMAIL - USERNAME - IF AUTHENTICATION REQUIRED
Const cdoPassword = "L337^p@$$w0rD"			'EMAIL - PASSWORD - IF AUTHENTICATION REQUIRED

'' Path information specific to the machine running on. 
Dim   cPath: cPath = "."					'WHERE ARE THE INPUT / OUTPUT FILES FOR THIS SERVER
Dim   cAppPath: cAppPath = "C:\Program Files (x86)\Dovestones Software\True Last Logon" 'WHERE IS THE INSTALLED PATH
Const cTLLAPP = "TrueLastLogonCLI.exe"		'WHAT IS THE APPLICATION FILE NAME IN THE INSTALLED PATH

Const cDisable = 1 							'DISABLE THE USERS 1 == TRUE || 0 == FALSE
Const cVer = "2.6.4"						'CURRENT VERSION, MAJOR CHANGES SHOULD REFLECT IN MAJOR.MINOR. Major version increments
											' should only change for big changes, tweaks and tuning should be minor increments.
Const cDaysExpire = 60						'NUMBER OF DAYS WE ALLOW USERS TO BE INACTIVE SAS70==60 days, PCI==90 days
Const cDaysIgnore = 10						'NUMBER OF DAYS WE ALLOW USERS TO BE NEW

''=================================================================================================================================
''~~~~~~~~~~~~~~~~~~~ THERE ARE NO VARIABLE DEFINATIONS BEYOND HERE THAT WOULD REQUIRE ANY TYPE OF MODIFICATION ~~~~~~~~~~~~~~~~~~~
''=================================================================================================================================
Const cForReading = 1						'FILE READ VALUE FOR fso.OpenTextFile
Const cForWriting = 2						'FILE WRITE VALUE FOR fso.OpenTextFile
Const cForAppending = 8						'FILE APPEND VALUE FOR fso.OpenTextFile

Const cdoAnonymous = 0 						'EMAIL - NO AUTH NEEDED 
Const cdoBasic = 1 				 			'EMAIL - CLEAR-TEXT AUTH
Const cdoNTLM = 2  							'EMAIL - NTLM AUTH

'' This is a custom class that we use to store data on a person.
Class User
	Public Name
	Public LastLogonTimeStamp
	Public Enabled
	Public Locked
	Public pwdLastSet
	Public pwdNeverExpires
	Public whenCreated
	Public whenChanged
	Public distName
End Class

'WScript.Echo "!ADUM:" & Month(Now()) & "." & Day(Now()) & "." & Year(Now()) & " " & Hour(Now()) & ":" & Minute(Now())

''Define variables
ReDim arrUserExcept(1,0)					'we need to be able to resize as it grows for each exception we process
ReDim arrUser(0)							'we need to be able to resize as it grows for each user we find

Dim objFSO, objIFile, objOFile, objRFile 	'FileSystemObject, Input, Output, Report
Dim objShell, objExec, objNet				
Dim strTLLParams, strTmpLine, strListDCs
Dim iCntDCs
Dim i, j, k, l, t							'junk counters, i think there are desc when i get to them
Dim strDebugFile, _
	strUserExceptionFile, _
	strUserExceptionString, _
	strTLLFile, _
	strReportFile, _
	strDomain, _
	strJunk, _
	strLorX
Dim varStartTime, varEndTime, vTT1

varStartTime = Now() 'so we can record and calculate how long we are running

''Since we need to know the full path to the files, lets see if we can collect this from the running direcroty if cPath is `.`
''We can't use .GetParentFolderName, since is would be "" 
If cPath = "." Then
	strJunk = WScript.ScriptFullName
	i = InStr(strJunk, WScript.ScriptName)
	cPath = Left(strJunk, (i - 2))
End If

''These are our input/output files for debugging, exception list, etc. The 
''debugging and report files are attached in email as well
strDebugFile = cPath & "\adum.debug.txt"
strUserExceptionFile = cPath & "\adum.exceptions.lst"
strReportFile = cPath & "\adum.actions." & Day(Now()) & MonthName(Month(Now())) & Year(Now()) & ".csv"
strTLLFile = cPath & "\adum.report." & Day(Now()) & MonthName(Month(Now())) & Year(Now()) & ".csv"

''Create the objects that we need
Set objFSO = CreateObject("Scripting.FileSystemObject")
Set objOFile = objFSO.CreateTextFile(strDebugFile, True) 'overwrite any existing file or data in that file
Set arrUser(0) = New User
Set objNet = CreateObject("WScript.Network")
Set objRFile = objFSO.CreateTextFile(strReportFile, True) 'overwrite any existing file or data in that file

''Here we need to put in the headers for our CSV file...
objRFile.WriteLine "Username,Last Logon Timestamp,Enabled,Locked,Password Never Expires,Password Last Set,When Account Created,When Account Changed,Distinguished Name"

''Write some header information to the debug lof file
WriteDebugLog("ADUM Debug Log File -- Generated: " & varStartTime)
WriteDebugLog(" Application: " & cAppPath & "\" & cTLLApp)
WriteDebugLog(" Debug File: " & strDebugFile)
WriteDebugLog(" Exception File: " & strUserExceptionFile)
WriteDebugLog(" Report Output File: " & strReportFile)
WriteDebugLog(" TrueLastLogon Input File: " & strTLLFile)
WriteDebugLog(" Execution Server: " & objNet.ComputerName)
WriteDebugLog("============================================================")
WriteDebugLog("")

''Check to make sure the application is present, if not dump out quick
If Not objFSO.FileExists(cAppPath & "\" & cTLLApp) Then
	WriteDebugLog("Could not find " & cTLLApp & " executable in " & cAppPath & "\" & cTLLApp)
	objOFile.Close
	WScript.Quit (9000)
End If

''Check to make sure we have the exception list file as well. Without this we will have MAJOR problems with everything
If Not objFSO.FileExists(strUserExceptionFile) Then
	WriteDebugLog("DANGER WILL ROBINSON .... DANGER!!!!" & vbCrLf & _
		" @@@ COULD NOT FIND THE EXCEPTION LIST FILE " & struserExceptionFile & vbCrLf & _
		" @@@ We can not continue without this file.")
	objOFile.Close
	WScript.Quit (9001)
End If

''Call the CountDCs() so we can get a count of the domain controllers we have 
'' and remove the GASLGCT02 from the list so we can then pass this cleaned list
'' to TrueLastLogonCLI with the /DC flag
iCntDCs = CountDCs

''Get ready to call the TrueLastLogonCLI program with some params and save the report output
strTLLParams = " /format:csv /file:" & Chr(34) & strTLLFile & Chr(34) & _
	" /domain:innotrac.com /ou:dc=innotrac,dc=com /log /object:user /dc:" & strListDCs & _
	" /columns:sAMAccountName,lastLogonTimeStamp,Enabled,Lockout,PasswordNeverExpires,pwdLastSet,whenCreated,whenChanged,distinguishedName" & _
	" /quickfilterparams:" & cDaysExpire & " /quickfilter:NotLoggedOnInXDays"
WriteDebugLog("Arguements passed to " & cPath & "\" & cTLLApp & ": " & vbCrLf & vbTab & strTLLParams)

vTT1 = Now()
Set objShell = WScript.CreateObject("Wscript.Shell")
Set objExec = objShell.Exec(cAppPath & "\" & cTLLApp & strTLLParams)
WriteDebugLog(cTLLApp & " ProcessID is: " & objExec.ProcessID)

''Sleep holder while we execute, once status is zero {0} execution is complete
Do While objExec.Status = 0
	WScript.Sleep 1000
Loop

''Check to see if we exited cleanly
If objExec.ExitCode <> 0 Then
	WriteDebugLog("@@@ Error reported in the call to " & cTLLApp & vbCrLf & vbTab & "@@@ " & objExec.StdErr.ReadAll)
	WScript.Quit(9002)
End If

WriteDebugLog("Execution time: " & DateDiff("s", vTT1, Now()) & " seconds")

WriteDebugLog("Converted AD name " & ConvertADName(1) & " to domain name " & ConvertADName(0))

ReadExceptions 'Read in the exception list file

i = 0 'counter array position
j = 0 'counter user not enabled
k = 0 'counter user matched an exception
l = 0 'counter user disabled

''Check to see if we have the output file available for reading
If Not objFSO.FileExists(strTLLFile) Then
	WriteDebugLog("@@@@ ERROR: We did not find the output file that we were expecting from TrueLastLogon." & vbCrLf & _
		vbTab & "@@@ Missing: " & cPath & "\" & strTLLFile & " on server " & objNet.ComputerName)
	objOFile.Close
	WScript.Quit (9003)
End If

Set objIFile = objFSO.OpenTextFile(strTLLFile, cForReading)
strTmpLine = objIFile.ReadLine 'prime read and skip the first record, its a header and not needed
Do Until (objIFile.AtEndOfStream)
	strTmpLine = objIFile.ReadLine 'read in current line to buffer
	strTmpLine = Replace(strTmpLine, Chr(34), "") 'remove all the " that are in the string from the output
	strJunk = Split(strTmpLine, ",") 'split the clean line into a temp array
	ReDim Preserve arrUser(i) : Set arrUser(i) = New User 'we need to grow the 
	 ''array and make sure the new element is the User class as well as preserving the existing objects

''Assign each element of the temp array to the matching element in the class
	arrUser(i).Name = strJunk(0)
	arrUser(i).LastLogonTimeStamp = strJunk(1)
	arrUser(i).Enabled = strJunk(2)
	arrUser(i).Locked = strJunk(3)
	arrUser(i).pwdNeverExpires = strJunk(4)
	arrUser(i).pwdLastSet = strJunk(5)
	arrUser(i).whenCreated = strJunk(6)
	arrUser(i).whenChanged = strJunk(7)

''The distinguishedName has comma's in the output as it looks like CN=Guest,CN=Guest,DC=innotrac,DC=com and these
'' get split when we parse the line. We need to rejoin the line so it is correct. We also need to consider that
'' loading a file with comma's into an Excel CSV format Excel will split these back into seperate columns. So, when
'' we rebuild the distinguishedName field for output, we are going to use semi-colons `;` as the seperator. This
'' should not cause an issue with Excel, and be mininal to the user for readability.
	For t = 8 To UBound(strJunk)
		arrUser(i).distName = arrUser(i).distName & strJunk(t)
		If t < UBound(strJunk) Then arrUser(i).distName = arrUser(i).distName & "," 'this adds a trailing comma to the string
	Next
'' Debug output for displaying user object data
'	WScript.Echo "Name: " & arrUser(i).Name & vbCrLf & _
'		"TimeStamp: " & arrUser(i).LastLogonTimeStamp & vbCrLf & _
'		"Enabled: " & arrUser(i).Enabled & vbCrLf & _
'		"Locked: " & arrUser(i).Locked & vbCrLf & _
'		"Pwd Expires: " & arrUser(i).pwdNeverExpires & vbCrLf & _
'		"Pwd Last Set: " & arrUser(i).pwdLastSet & vbCrLf & _
'		"Created: " & arrUser(i).whenCreated & vbCrLf & _
'		"Changed: " & arrUser(i).whenChanged & vbCrLf & _
'		"Dist Name: " & arrUser(i).distName 
		
	If arrUser(i).Enabled Then 'check and see if accunt is enabled
		If SearchException(arrUser(i).Name) Then 'check if the user is on the exception list
			Select Case strLorX
				Case "L"
					WriteDebugLog("User " & arrUser(i).Name & " matched an entry in the exception file of `LIKE` pattern")
				Case "X"
					WriteDebugLog("User " & arrUser(i).Name & " matched an entry in the exception file of `EXACT` pattern")
				Case Else
					WriteDebugLog("User " & arrUser(i).Name & " matched an entry in the exception file of `UNKNOWN` pattern")
			End Select
			k = k + 1
		Else 'user is enabled & not an exception
			If cDisable Then 
				DisableAccount arrUser(i).Name
			Else
				WriteDebugLog("User " & arrUser(i).Name & " would be disabled, however this is turned off. Last logon date and time was " & arrUser(i).LastLogonTimeStamp)
			End If
		End If
	Else 'user is not enabled
		j = j + 1
	End If
	i = i + 1 'now increment the counter for the next pass
Loop

varEndTime = Now
WriteDebugLog("")
WriteDebugLog("============================================================")
WriteDebugLog(l & " users are requiring removal / disabling")
WriteDebugLog(k & " users were skipped for matching the exception list")
WriteDebugLog(j & " users were already disabled and skipped")
WriteDebugLog("")
WriteDebugLog("ADUM Debug Log File -- End: " & varEndTime)
WriteDebugLog("Total Run Time: " & DateDiff("S", varStartTime, varEndTime) & " in seconds")
WriteDebugLog("============================================================")

''Write a final line in the report CSV file with the date/time stamp
objRFile.WriteBlankLines(1)
objRFile.WriteLine "Run Date/Time," & FormatDateTime(Now(), 2) & "," & FormatDateTime(Now(), 3)

''close file handles
objOFile.Close
objIFile.Close
objRFile.Close

''Call the function to send email
GenerateEmail()

''Clean up a little more then quit
Erase arrUser
WScript.Quit

''=================================================================================================================================
''   _________																			  _________
''  /         \																			 /         \
'' ||         ||		FUNCTIONS LIVE UNDER THE BRIDGE AS DO TROLLS					||         ||
'' ||~~~~~~~~~||																		||~~~~~~~~~||
''=================================================================================================================================

Function WriteDebugLog(strLine)
''Write passed string to the debug file, adding the formatted time stamp
	If (strLine <> "") Then
		objOFile.WriteLine "[" & FormatDateTime(Now(), 3) & "] " & strLine
	Else
		objOFile.WriteBlankLines 1
	End If
End Function

Function DisableAccount(strU)
''Pass in the username, check to see if we are turned on to disable accounts (cDisable) then lookup the user account to get the
'' object regardless of where in AD it is. Change the .AccountDisabled status and write it back.
''
'' If there is an error in finding the user in the domain, then write a log entry and leave
''
	On Error Resume Next
	Dim objU, strS, intUAC, strDesc
	If cDisable Then

''We need to check the date that the account was created. If this is less than the cDaysIgnore, we treat the account as "new"
'' and skip the processing. This is because the LastLogonTimeStamp is empty, thus appearing to be > cDaysExpire.
		If DateDiff("d", arrUser(i).whenCreated, Now()) > cDaysIgnore Then
			strS = "WinNT://" & strDomain & "/" & strU
			Set objU = GetObject(strS)
			If Err.Number = 0 Then
				WriteDebugLog(" User " & arrUser(i).Name & " disabled. Path: " & arrUser(i).distName & " Last Logon: " & " (" & arrUser(i).LastLogonTimeStamp & ")")

				objRFile.WriteLine arrUser(i).Name & "," & arrUser(i).LastLogonTimeStamp & "," & arrUser(i).Enabled & _
					"," & arrUser(i).Locked & "," & arrUser(i).pwdNeverExpires & "," & arrUser(i).pwdLastSet & "," & _
					arrUser(i).whenCreated & "," & arrUser(i).whenChanged & "," & arrUser(i).distName

				'If Err.Number <> 0 Then WScript.Echo "error: " & Err.Number & " " & Err.Description
				
				''before we clobber the description, pull out anything that might be there, append the !TPC sting, then write the updated string
				If IsEmpty(objU.Description) Or IsNull(objU.Description) Or (objU.Description = Nothing) Then
					strDesc = "!ADUM:" & Month(Now()) & "." & Day(Now()) & "." & Year(Now())
				Else
					strDesc = "!ADUM:" & Month(Now()) & "." & Day(Now()) & "." & Year(Now()) & "(" & objU.Description & ")"
				End If
				
				objU.Description = strDesc
				objU.AccountDisabled = True
				objU.SetInfo
				l = l + 1 'incremement the counter for accounts that are actually disabled 
			Else 'Err.Number
				WriteDebugLog(" User " & arrUser(i).Name & " should have been disabled. However, there was an error finding them in " & strS & vbCrLf & _
					vbTab & "Error: " & Err.Number & " @@ " & Err.Source & vbCrLf & _
					vbTab & "Description: " & Err.Description)
			End If 'Err.Number

		Else 'DateDiff()

			WriteDebugLog("User " & arrUser(i).Name & " has not logged in and the account is less than " & cDaysIgnore & " old. whenCreated date is " & arrUser(i).whenCreated)
'			WScript.Echo("User " & arrUser(i).Name & " wC " & arrUser(i).whenCreated & " dDiff " & DateDiff("d", arrUser(i).whenCreated, Now()))			

		End If 'DateDiff()
	End If 'cDisable
End Function

Function ReadExceptions()
''Read through the exception file and load all items into a 2D array. This is 
'' because we allow both a Like match and an exact match in the exception file.
''
'' arrUserExc("L","bbpack") -- Like match will be applied to accounts starting with BBPACK???
'' arrUserExc("X","tfencl") -- eXact match will require exact match tfencl==tfencl
''
	Dim arrTmp, objIFile, strTmp, strC
	Set objIFile = objFSO.OpenTextFile(strUserExceptionFile, cForReading)
	i = 0

	Do Until (objIFile.atEndOfStream)
		strTmp = objIFile.ReadLine
		If (Left(strTmp, 2) <> "--") And (strTmp <> "") Then ' check for comment line
			arrTmp = Split(LCase(strTmp), ";") ' split on the ; into the temporary array
			strC = UCase(Trim(arrTmp(1))) ' force UPPER case on the 2nd element
			If (strC = "L" Or strC = "X") Then ' check to make sure we ONLY have an L or X
				ReDim Preserve arrUserExcept(1,i) ' resize the array making sure we preserve everything
				arrUserExcept(0,i) = arrTmp(0) ' this has the user name
				arrUserExcept(1,i) = arrTmp(1) ' this has the type of matching Like or eXact
				strTmp = "Added " & arrTmp(0)
				If Trim(UCase(arrTmp(1))) = "L" Then
					strTmp = strTmp & "* to the arrUserExcept array"
				Else
					strTmp = strTmp & " to the arrUserExcept array"
				End If

				WriteDebugLog(strTmp)

				i = i + 1
			Else ' if not L or X
				WriteDebugLog("User " & arrTmp(0) & " is skipped in adding to the exception list because it has " & _
					strC & " as the 2nd parameter and it should be either L or X")
				WriteDebugLog("  --- full string: " & strTmp)
			End If ' not L or X
		End If ' not comment line
	Loop

	WriteDebugLog("")
	WriteDebugLog("============================================================")
	WriteDebugLog("** Exceptions Added: " & UBound(arrUserExcept,2) & " **")
	WriteDebugLog("============================================================")
	WriteDebugLog("")

	objIFile.Close
End Function

Function CountDCs()
''As of 02/06/2012 this is really not needed any longer. We originally had this 
'' hear as we collected the number of servers and server names. The count now
'' goes into the email message and is useful as informational.
''
'' 09.04.2012 - build a list of DC's into strListDCs and remove GASLGCT02
''
	Dim objS, objDom, objRoot, sTmp, iA
	i = 0
	Set objRoot = GetObject("LDAP://RootDSE")
	Set objDom = GetObject("LDAP://" & objRoot.Get("defaultNamingContext"))
	strDomain = Mid(objDom.ADSPath, 8)
	Set objDom = GetObject("LDAP://OU=Domain Controllers," & strDomain)
	For Each objS In objDom
	''Cut the $ from the end of the copmuter name then build a string of comma
	'' seperated server names that are domain controllers skipping GASLGCT20
		iA = Len(objS.displayName)
		'' if object displayName is null Left() crashes, check Len first
		If (iA > 0) Then
			sTmp = Left(objS.displayName, iA - 1)
		End If
		If (sTmp <> "GASLGCT02") Then
			If (Len(strListDCs) = 0) Then
				strListDCs = sTmp
			Else
				strListDCs = strListDCs & "," & sTmp
			End If
			i = i + 1
		End If
	Next
'	WScript.Echo strListDCs
	CountDCs = i
End Function

Function SearchException(strUser)
''We now have to determine if this is a eXact pattern match, or a Like pattern match. If the exception has an L, then 
'' we need to get the length of the exception name, then match to the same length of the passed user. If that returns 
'' exact then the LIKE condition is met.
	Dim iPos, iLen1, iLen2
	Dim strX, strC

	For iLen1 = 0 To UBound(arrUserExcept, 2)
		strC = UCase(Trim(arrUserExcept(1, iLen1)))
		Select Case strC
			Case "L"
				strX = Left(strUser, Len(arrUserExcept(0, iLen1)))
			Case "X"
				strX=strUser
			Case Else
				WriteDebugLog("User " & strUser & " is skipped in adding to the exception list because it has " & _
					strC & " as the 2nd parameter and it should be either L or X")
		End Select

		iPos = StrComp(strX, arrUserExcept(0, iLen1), vbTextCompare)

		If iPos = 0 Then
			SearchException = True
			strLorX = strC 'allow to send back either X or L so we can add to the debug if exact match or like pattern
			Exit Function
		End If
	Next
	SearchException = False
End Function

Function ConvertADName(blnLDAP)
''Just grab the naming standard from AD, then convert it from DC=Domain,DC=COM to Domain.COM for use with WinNT query
	Dim oRoot, oDom, strD
	Set oRoot = GetObject("LDAP://RootDSE")
	Set oDom = GetObject("LDAP://" & oRoot.Get("defaultNamingContext"))
	strDomain = Mid(oDom.ADSPath, 8)
	If blnLDAP Then 'If all we need is the LDAP DC=Domain,DC=COM
		ConvertADName = strDomain
	Else 'We need the Domain.COM for the WinNT string
		strD = "LDAP Domain is: " & strDomain
		strDomain = Replace(strDomain, "DC", "")
		strDomain = Replace(strDomain, "=", "")
		strDomain = Replace(strDomain, ",", ".")
		ConvertADName = strDomain
	End If
End Function

Function GenerateEmail()
''Here we have completed running, matching users, and disabling ones that are needed
	Dim objEMail, strOut
	Set objEMail = CreateObject("CDO.Message")	

	objEMail.Configuration.Fields.Item ("http://schemas.microsoft.com/cdo/configuration/sendusing") = 2
	objEMail.Configuration.Fields.Item ("http://schemas.microsoft.com/cdo/configuration/smtpserver") = cSMTPServer
	objEMail.Configuration.Fields.Item ("http://schemas.microsoft.com/cdo/configuration/smtpserverport") = 25
	objEMail.Configuration.Fields.Item ("http://schemas.microsoft.com/cdo/configuration/smtpauthenticate") = cdoAnonymous
	''******************************************************************************
	''***** IF MAIL FAILES, YOU MIGHT NEED TO AUTHENTICATE TO THE MAIL SERVER, TRY cdoBasic FIRST
	''***** IF YOU DON'T NEED TO AUTHENTICATE, REMARK THE NEXT 2 LINES OUT
	''******************************************************************************
	'objMail.Configuration.Fields.Item ("http://schemas.microsoft.com/cdo/configuration/sendusername") = cdoUserName
	'objMail.Configuration.Fields.Item ("http://schemas.microsoft.com/cdo/configuration/sendpassword") = cdoPassword
	''
	''Actual body of the message. I know, a lot of work just to send a message but hey, what are you going to do! :-)
	objEMail.From = cFrom
	objEMail.To = cTo
	objEMail.CC = cCC
	objEMail.Subject = cSubject
	objEMail.TextBody = "We have run the ADUM script to detect all users that have been inactive " & cDaysExpire & _
	" or more days. This is determined by the LastLogon and/or LastLognonTimeStamp field on the each user" & _
	" account. We query a total of " & CountDCs() & " Domain Controllers in the " & ConvertADName(0) & _
	" domain to make sure we have the most recent information on each user since .LastLogonDate, " & _
	".LastLogonTime and .LastLogonTimeStamp are not synchronized across DC's." & _
	vbCrLf & _
	vbCrLf & _
	"We use TrueLastLogon (TLL) program to build the list of users that have been inactive and then have " & _
	"this script (" & WScript.ScriptName & ") take the output file from TLL as input to check to see if " & _
	"the user is already disabled; if the user matches a list of exceptions in the " & strUserExceptionFile & _
	" file; and then if all other conditions are met properly we disable the account." & _
	vbCrLf & _
	vbCrLf & _
	"The attached 2 files are: " & vbCrLf & _
	vbTab & strDebugFile & " - debug log file with detailed information during execution." & vbCrLf & _
	vbTab & strReportFile & " - csv file that has the users that were disabled and the detail information " & _
	"on each account." & _
	vbCrLf & _
	vbCrLf & _
	"Currently, the account is only disabled in the OU it lives in. We do not move the account to a " & _
	"generic OU. We are now running v3 of the TrueLastLogon software and in this new version we can " & _
	"collect the LDAP distinguishedName field and include it in the report for greater detail in isolating " & _
	"users location that are disabled." & _
	vbCrLf & _
	vbCrLf & _
	"In the latest run we found the following: (" & Now() & ")" & vbCrLf & _
	vbTab & (UBound(arrUser) + 1) & " users that require review" & vbCrLf & _
	vbTab & l & " users were disabled" & vbCrLf & _
	vbTab & k & " users were skipped for matching the exception list" & vbCrLf & _
	vbTab & j & " users were already disabled and skipped" & vbCrLf & _
	vbCrLf & _
	"The total run time: " & DateDiff("S", varStartTime, varEndTime) & " (in seconds)" & _
	vbCrLf & _
	vbCrLf & _
	"Thank you," & vbCrLf & _
	"Mr. Roboto" & vbCrLf & _
	"Version: " & cVer

	objEMail.AddAttachment strDebugFile
	objEMail.AddAttachment strReportFile

	objEMail.Configuration.Fields.Update
	objEMail.Send
End Function