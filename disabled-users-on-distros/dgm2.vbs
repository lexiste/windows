Option Explicit
'On Error Resume Next

'' 2014.01.20 - removed the abilities that called the getMail.vbs to collect the
''  approx mailbox size of each user. This feature broke sometime recently and 
''  I've not been able to resolve the issue so removing the feature so that at
''  least the report runs and collects the members of distro's and if they are
''  disabled.
''
'' 2014.05.15 - changed a check in the strMember that used to check for the
''  word `template` and now check for the underscore character `_`. This is
''  because Chicago changed their nameing standard for user accounts that are
''  used as templates.
''
'' 2015.09.15 - added IF..THEN..ELSE to check the length of month and day and if
''  the length is 1 character prepend a zero (0) before the value
''
'' 2015.09.15 - add function to send mail to the NOC if a disabled account is found
''  in the email only send the user name in the message body, we can also
''  attache the entire report file for reference
''
'' 2015.11.10 - NOC found that template accounts are getting reported since they
''  are members of distro groups.  Looking in AD, it looks like template accounts
''  sAMAccountName start with an underscore (_) character.  Add a simple check
''  in the CheckUser() to skip accounts with an underscore as the first char.
''
'' 2016.11.09 - change cSMTPServer from smtpmail.innotrac.com to mailhost.innotrac.com
''

''#### VARIABLES THAT MIGHT NEED TWEAKED
Const cTo = "it_noc@innotrac.com"
'Const cTo = "tfencl@innotrac.com"
Const cCC = "tfencl@innotrac.com"
Const cSMTPServer = "mailhost.innotrac.com"
Const cFrom = "helpdesk@innotrac.com"
Const cSubject = "Disabled Users Distribution List Clean-Up"

''Most likely not needed, but if needed to pass authorization for connecting and sending emails
Const cdoAnonymous = 0 						'EMAIL - NO AUTH NEEDED 
Const cdoBasic = 1 				 			'EMAIL - CLEAR-TEXT AUTH
Const cdoNTLM = 2  							'EMAIL - NTLM AUTH
Const cdoUserName = "account@domain.com"	'EMAIL - USERNAME - IF AUTHENTICATION REQUIRED
Const cdoPassword = "L337^p@$$w0rD"			'EMAIL - PASSWORD - IF AUTHENTICATION REQUIRED

Const ForReading = 1
Const ForWriting = 2
Const ForAppending = 8
Const HomeDir = "\\gajcfnp01.innotrac.com\tfencl$\scripts\prod\distros"

Const cVER = "1.2.3"

''=================================================================================================================================
''~~~~~~~~~~~~~~~~~~~ THERE ARE NO VARIABLE DEFINATIONS BEYOND HERE THAT WOULD REQUIRE ANY TYPE OF MODIFICATION ~~~~~~~~~~~~~~~~~~~
''=================================================================================================================================

Dim objConnection, objCommand, objRootDSE, objRecordSet, objFSO
Dim strDNSDomain, strFilter, strQuery, strAttributes, strBase, strDN, strSA, strCN, strEmailBodyUsers
Dim gt, file, dlog, scope, secdist, i
Dim intEmailBodyUsers

Initialize

Set objConnection = CreateObject("ADODB.Connection")
Set objCommand = CreateObject("ADODB.Command")
objConnection.Provider = "ADsDSOOBject"
objConnection.Open "Active Directory Provider"
Set objCommand.ActiveConnection = objConnection
Set objRootDSE = GetObject("LDAP://RootDSE")

''Get domain
strDNSDomain = objRootDSE.Get("defaultNamingContext")
strBase = "<LDAP://" & strDNSDomain & ">"

''Define the filter elements
strFilter = "(&(objectCategory=group))"

''List all attributes you will require
strAttributes = "distinguishedName,sAMAccountName,groupType,cn"

''compose query
strQuery = strBase & ";" & strFilter & ";" & strAttributes & ";subtree"
objCommand.CommandText = strQuery
objCommand.Properties("Page Size") = 99999
objCommand.Properties("Timeout") = 300
objCommand.Properties("Cache Results") = False
Set objRecordSet = objCommand.Execute
objRecordSet.MoveFirst

Do Until objRecordSet.EOF
    strCN = objRecordSet.Fields("cn")
    strDN = objRecordSet.Fields("distinguishedName")
    strSA = objRecordSet.Fields("sAMAccountName")
    gt = objRecordSet.Fields("groupType")
    If (gt And &h01) Then ''group created by system
    scope = "S"
    ElseIf (gt And &h02) Then ''group with global scope
    scope = "G"
    ElseIf (gt And &h04) Then ''group with domain local scope
    scope = "D"
    ElseIf (gt And &h08) Then ''group with universal scopt
    scope = "U"
    End If
    If (gt And &h80000000) Then ''security group
     secdist = "Security"
    Else
     secdist = "Distribution"
    End If
        
    Select Case scope
      Case "S"
         WriteLogLine vbCrLf & "Name" & vbTab & strDN & vbCrLf & "Scope" & vbTab & "System Built-In " & secdist
      Case "G"
         WriteLogLine vbCrLf & "Name" & vbTab & strDN & vbCrLf & "Scope" & vbTab & "Global " & secdist
      Case "D"
         WriteLogLine vbCrLf & "Name" & vbTab & strDN & vbCrLf & "Scope" & vbTab & "Domain " & secdist
      Case "U"
         WriteLogLine vbCrLf & "Name" & vbTab & strDN & vbCrLf & "Scope" & vbTab & "Universal " & secdist
    End Select
    
    If secdist = "Distribution" Then
        i = i + 1
'        WScript.Echo "Distro >> " & strDN
        FindMember(strDN)
    End If
    
    objRecordSet.MoveNext
Loop

Exiting

''=================================================================================================
'' Functions can be found below
''=================================================================================================

Function FindMember(DNpath)
   On Error Resume Next
   Dim objGrp, arrMember, strMember, result, v
   If InStr(1, DNpath, "/") Then DNpath = Replace(DNpath, "/", "\/")
   Set objGrp = GetObject("LDAP://" & DNpath)
   objGrp.GetInfo
   v = objGrp.GetEx("member")
   If Err.Number <> 0 Then
      WriteDebugLog vbTab & "Could not find member(s) in the object.member property for " & DNpath
      WriteLogLine vbTab & "Could not find any members for this group"
      Err.Clear
   Else
      arrMember = objGrp.GetEx("member")
      WriteLogLine "Members of " & DNpath
      For Each strMember In arrMember
      '' Chicago TSS creates user accounts that are solely for used as templates for deptartments.
      '' They used to use the word template in the name, however, that changed but they do always
      '' use the underscore `_` as the 1st character so if we find it, let's skip it.
        If (InStr(1, strMember, "_", 1) = 0) Then
          result = CheckUser(strMember)
          WriteLogLine vbTab & strMember & result
        End If
      Next
   End If
End Function

Function CheckUser(user)
   On Error Resume Next
   Dim objUsr, v, strTmp, bolUser, strU
   Dim objMailSize, vMailSize, intMailSize
   Dim intOverHardQuotaLimit, intOverQuotaLimit, intStorageQuota, bolUseMailStoreDefaults
    
   If InStr(1, user, "/") Then user = Replace(user, "/", "\/")
   Set objUsr = GetObject("LDAP://" & user)
   objUsr.GetInfo

    ''pull the value of this attribute, then we can check for 1) an error / non user 2) that the user is Person record
    v = objUsr.objectCategory
    strU = objUsr.sAMAccountName ''useful really for debugging so we can see the value in the object
    
'    If InStr(1, objUsr.sAMAccountName, "GALV") Then
'    	WScript.Echo "sAMAccount: " & vbTab & objUsr.sAMAccountName
'    End If
    
    bolUser = False
    If InStr(1, LCase(v), "person") > 0 Then
        If ((Len(objUsr.sAMAccountName) > 0) And (Left(objUsr.sAMAccountName,1) <> "_")) Then
            bolUser = True
        End If
    End If

    If ((Err.Number = 0) And bolUser) Then
    	If objUsr.AccountDisabled Then
	    	strTmp = strTmp & vbTab & "[disabled account]"
	        If (InStr(1, strEmailBodyUsers, user, vbTextCompare)) = 0 Then
	        	strEmailBodyUsers = strEmailBodyUsers & user & vbCrLf
	            intEmailBodyUsers = intEmailBodyUsers + 1
			End If '' InStr()
		End If '' .AccountDisabled
    End If ''if err.number = 0
    
    v = ""
    strU = Null
    
    CheckUser = strTmp
End Function

Function DN2CN(strDN, strCN, intDomLen)
   Dim noDomain, ou, count, length, i
   noDomain = Left(strDN, Len(strDN) - intDomLen - 1)
   count = 0
   For i = 1 To Len(noDomain)
      If Mid(noDomain, i, 1) = Chr(44) Then
         count = count + 1
      End If
   Next
   
   length = Len(strCN) + count + 3
   ou = Right(noDomain, Len(noDomain) - length)
   
   If ou = "" Then
      DN2CN = "<NONE>"
   Else
      ou = Right(ou, Len(ou) - 1)
      ou = Replace(ou, "OU=", "")
      ou = Replace(ou, "CN=", "")
      DN2CN = ou
   End If  
End Function

Function WriteLogLine(message)
   Dim attempt, oF
   attempt = 0
   Do
      On Error Resume Next
      Set oF = objFSO.OpenTextFile(file, ForAppending, True)
      If Err.Number = 0 Then
         oF.WriteLine message
         oF.Close
         Exit Function
      Else
         WScript.Echo Err.Number & " @@ " & Err.Description
      End If
      On Error Goto 0
      Randomize
      WScript.Sleep 1000 + Rnd * 100
      attempt = attempt + 1
   Loop Until attempt >= 10
End Function

Function WriteDebugLog(message)
   Dim attempt, oF
   attempt = 0
   Do
      On Error Resume Next
      Set oF = objFSO.OpenTextFile(dlog, ForAppending, True)
      If Err.Number = 0 Then
         oF.WriteLine message
         oF.Close
         Exit Function
      Else
         WScript.Echo Err.Number & " @@ " & Err.Description
      End If
      On Error Goto 0
      Randomize
      WScript.Sleep 1000 + Rnd * 100
      attempt = attempt + 1
   Loop Until attempt >= 10
End Function

Function Initialize
   Set objFSO = CreateObject("Scripting.FileSystemObject")
   Dim iMon, iDay
   
   'Check the length value for month and day and if == 1 add a leading zero (0)
   If Len(Month(Now)) = 1 Then 
   	iMon = "0" & Month(Now)
   Else
   	iMon = Month(Now)
   End If
   If Len(Day(Now)) = 1 Then
   	iDay = "0" & Day(Now)
   Else
   	iDay = Day(Now)
   End If
   
   file = HomeDir & "\distro.group.members." & Year(Now) & "-" & iMon & "-" & iDay & ".txt"
   dlog = HomeDir & "\distro.group.members.debug.log"
   
   WriteLogLine "===== Start " & WScript.ScriptName & " " & Now
   WriteLogLine "===== List all groups regardless of security | distribution, but expand members for distro lists"
   WriteDebugLog "====================================================================="
   WriteDebugLog "===== Start " & WScript.ScriptName & " Debug Log " & Now
   
   strEmailBodyUsers = ""
   intEmailBodyUsers = 0
End Function

Function Exiting
   objConnection.Close
   WriteLogLine vbCrLf & "Distribution Lists Counted: " & i
   WriteLogLine vbCrLf & "===== End " & WScript.ScriptName & " " & Now
   WriteDebugLog vbCrLf & "===== End " & WScript.ScriptName & " " & Now
   WriteDebugLog "====================================================================="
   
   If Len(strEmailBodyUsers) > 0 Then GenerateEmail
   
   Set objConnection = Nothing
   Set objCommand = Nothing
   Set objRootDSE = Nothing
   Set objRecordSet = Nothing
End Function

Function GenerateEmail()
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
	objEMail.TextBody = "I've searched through the distribuion lists and collected information on the users" & _
	 " that are members of each list.  I then cross-referenced that with the AD account of the user to see if" & _
	 " if their account is enabled.  If the users account is disabled, I added them to a list and emailed" & _
	 " that list to Santa Clause.  Not really, but I am providing you with this list so the users AD account can" & _
	 " be reviewed and the distribution lists can be removed.  That list contains " & intEmailBodyUsers & " unique" & _
	 " accounts of disabled users still on distribution lists." & _
	 vbCrLf & _
	 vbCrLf & _
	 "I have also attached both report and log files of the entire amount of work I have done.  The answer is 42," & _
	 " but now you know the question that was asked so there is meaning to my existence." & _
	vbCrLf & _
	vbCrLf & _
	"Begin list of disabled user accounts that are still a member of at least one (1) distribution list:" & _
	vbCrLf & _
	"================================================================================" & vbCrLf & _
	strEmailBodyUsers & _
	"================================================================================" & vbCrLf & _
	vbCrLf & _
	vbCrLf & _
	"Thank you," & vbCrLf & _
	"Mr. Roboto" & vbCrLf & _
	"Version: " & cVer

	objEMail.AddAttachment file
'	objEMail.AddAttachment dlog

	objEMail.Configuration.Fields.Update
	objEMail.Send
End Function