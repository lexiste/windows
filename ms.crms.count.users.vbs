Option Explicit
On Error Resume Next

'' Updates / Modifications
'' 08.Sept.2015_0900 - removed Ed Ringer (eringer@innotrac.com) from cCC line
''
'' 05.Apr.2017_1400 - changed cSMTPServer, removed lsizemore email address
''

''### VARIABLES THAT MIGHT NEED TWEAKED ###
''Needed for sending email, To, CC, mail server
Const cVer = "1.0.2"

''START TESTING CONFIG
'Const cTo = "tfencl@innotrac.com, msanford@innotrac.com"
'Const cCC = ""
''END TESTING CONFIG

Const cTo = "ljackson@radial.com"			'WHO ARE WE SENDING EMAIL TO
Const cCC = "tfencl@radial.com,msanford@radial.com,rhollinger@radial.com,jschuler@radial.com"			'WHO TO CC IF ANY
Const cSMTPServer = "mailhost.innotrac.com"	'EMAIL - EXCHANGE SERVER
Const cFrom = "helpdesk@innotrac.com"		'EMAIL - WHO FROM
Const cSubject = "Monthly MS CRMS Seat Count"	'EMAIL - SUBJECT LINE

''Most likely not needed, but if needed to pass authorization for connecting and sending emails
Const cdoAnonymous = 0 						'EMAIL - NO AUTH NEEDED 
Const cdoBasic = 1 				 			'EMAIL - CLEAR-TEXT AUTH
Const cdoNTLM = 2  							'EMAIL - NTLM AUTH
Const cdoUserName = "account@domain.com"	'EMAIL - USERNAME - IF AUTHENTICATION REQUIRED
Const cdoPassword = "L337^p@$$w0rD"			'EMAIL - PASSWORD - IF AUTHENTICATION REQUIRED

Dim strOU, objConn, objCmd, objRS, iRec, strMsg

strOU = "ou=MS Clientlogic,ou=Client Logons,ou=Reno,dc=INNOTRAC,dc=COM"

Set objConn = CreateObject("ADODB.Connection")
objConn.Open "Provider=ADsDSOObject;"

Set objCmd = CreateObject("ADODB.Command")
objCmd.ActiveConnection = objConn
objCmd.Properties("Page Size") = 1000

objCmd.CommandText = _
  "<LDAP://" & strOU & ">;" & _
  "(&(objectclass=user)(objectcategory=person)(!(userAccountControl:1.2.840.113556.1.4.803:=2)));" & _
  "adspath,distinguishedname,sAMAccountName,Name;subtree"
Set objRS = objCmd.Execute

objRS.MoveFirst
iRec = 0

Do Until objRS.EOF
	strMsg = strMsg &  objRS.Fields("Name").Value & vbCrLf
	objRS.MoveNext
	iRec=iRec + 1
Loop

strMsg = strMsg & vbCrLf & _
	vbCrLf & _
	"=========================" & vbCrLf & _
	"| Users Counted: " & iRec & vbCrLf & _
	"=========================" & vbCrLf

GenerateEmail

objRS.Close
Set objRS = Nothing
Set objCmd = Nothing
objConn.Close
Set objConn = Nothing

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
	objEMail.TextBody = "Monthly automated run to count and display the number of active users in the `" & _
		strOU & "` container. Only active accounts are listed and counted." & vbCrLf & vbCrLf & _
		strMsg & vbCrLf & vbCrLf & _
		"Thank you," & vbCrLf & _
		"Mr. Roboto" & vbCrLf & _
		"Version: " & cVer

	objEMail.Configuration.Fields.Update
	objEMail.Send
	If Err.Number<>0 Then
		MsgBox("error")
	End If
End Function
