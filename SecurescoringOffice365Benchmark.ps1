#Author: @nasamoskva
#Date: 2020-10-27
#Version: 1.0


$credential  = Get-Credential
$scoresuccess = @{}
$scorefailed = @{}
Import-Module "C:\Program Files\Common Files\Skype for Business Online\Modules\SkypeOnlineConnector\SkypeOnlineConnector.psd1"
$auth = New-CsOnlineSession -Credential $credential
Import-PSSession $auth
Import-Module Microsoft.Online.SharePoint.PowerShell -DisableNameChecking
Connect-MsolService -Credential $credential
Connect-ExchangeOnline -Credential $credential
$input = Read-Host -Prompt 'Please enter your sharepoint tenat name:'
$sharepointuri = "https://" + $input + "-admin.sharepoint.com"
$Body = @{
scope = "https://graph.microsoft.com/.default"
grant_type = "client_credentials"
client_id = Read-Host -Prompt 'Please enter your application id'
client_secret = Read-Host -Prompt 'Please enter your client secret'
}
$input1 = Read-Host -Prompt 'Please enter your tenat id:'
$uri = "https://login.microsoftonline.com/" + $input1 + "/oauth2/v2.0/token"
$token = Invoke-RestMethod -ContentType 'application/x-www-form-urlencoded' -Method 'POST' -Body $Body -Uri $uri
$header = @{ Authorization = "$($token.token_type) $($token.access_token)" }
Connect-SPOService -Url $sharepointuri -Credential $credential
function AzureActiveDirectory {
    #1.1.1 --------------------------------------------------------------------------------------

    (Invoke-WebRequest -Uri https://graph.microsoft.com/v1.0/security/secureScores?$top=1 -Headers $Header -Method Get -ContentType 'application/json' -UseBasicParsing | Select -ExpandProperty Content) -match "\WcontrolName\W:\WAdminMFAV2\W,\Wdescription\W:.*?\Wscore\W:(\d+\.\d)"
    $maxscore = (Invoke-RestMethod -Uri https://graph.microsoft.com/v1.0/security/secureScoreControlProfiles -Headers $Header -Method GET -ContentType 'application/json').value | Select-Object id,maxScore | Where-Object {$_.id -eq "AdminMFAV2"} | Select -ExpandProperty maxScore
    if($Matches[1] -eq $maxscore){
        $scoresuccess.Add('1.1.1 Ensure multifactor authentication is enabled for all users in administrative roles', 'Success with score : ' + $Matches[1] + ' and maxScore is : ' + $maxscore)
    }
    else{
        $scorefailed.Add('1.1.1 Ensure multifactor authentication is enabled for all users in administrative roles', 'Failure with score : ' + $Matches[1] + ' and maxScore is : ' + $maxscore)
    }
    
    #1.1.2 --------------------------------------------------------------------------------------

    (Invoke-WebRequest -Uri https://graph.microsoft.com/v1.0/security/secureScores?$top=1 -Headers $Header -Method Get -ContentType 'application/json' -UseBasicParsing | Select -ExpandProperty Content) -match "\WcontrolName\W:\WMFARegistrationV2\W,\Wdescription\W:.*?\Wscore\W:(\d+\.\d)"
    $maxscore = (Invoke-RestMethod -Uri https://graph.microsoft.com/v1.0/security/secureScoreControlProfiles -Headers $Header -Method GET -ContentType 'application/json').value | Select-Object id,maxScore | Where-Object {$_.id -eq "MFARegistrationV2"} | Select -ExpandProperty maxScore
    if($Matches[1] -eq $maxscore){
        $scoresuccess.Add('1.1.2 Ensure multifactor authentication is enabled for all users in all roles', 'Success with score : ' + $Matches[1] + ' and maxScore is : ' + $maxscore)
    }
    else{
        $scorefailed.Add('1.1.2 Ensure multifactor authentication is enabled for all users in all roles', 'Failure with score : ' + $Matches[1] + ' and maxScore is : ' + $maxscore)
    }

    #1.1.3 --------------------------------------------------------------------------------------


    $role = Get-MsolRole -RoleName "Company Administrator"
    $a = ( Get-MsolRoleMember -RoleObjectId $role.objectid | Select -ExpandProperty "EmailAddress")
    $b = $null -eq $a
    if($b -eq $false ) {
        $scoresuccess.Add('1.1.3 Ensure that between two and four global admins are designated', 'Success')
    }
    else { 
        $scorefailed.Add('1.1.3 Ensure that between two and four global admins are designated', 'Failure')
    }

    #1.1.4 --------------------------------------------------------------------------------------

    (Invoke-WebRequest -Uri https://graph.microsoft.com/v1.0/security/secureScores?$top=1 -Headers $Header -Method Get -ContentType 'application/json' -UseBasicParsing | Select -ExpandProperty Content) -match "\WcontrolName\W:\WSelfServicePasswordReset\W,\Wdescription\W:.*?\Wscore\W:(\d+\.\d)"
    $maxscore = (Invoke-RestMethod -Uri https://graph.microsoft.com/v1.0/security/secureScoreControlProfiles -Headers $Header -Method GET -ContentType 'application/json').value | Select-Object id,maxScore | Where-Object {$_.id -eq "SelfServicePasswordReset"} | Select -ExpandProperty maxScore
    if($Matches[1] -eq $maxscore){
        $scoresuccess.Add('1.1.4 Ensure self-service password reset is enabled', 'Success with score : ' + $Matches[1] + ' and maxScore is : ' + $maxscore)
    }
    else{
        $scorefailed.Add('1.1.4 Ensure self-service password reset is enabled', 'Failure with score : ' + $Matches[1] + ' and maxScore is : ' + $maxscore)
    }

    #1.1.6 --------------------------------------------------------------------------------------

    (Invoke-WebRequest -Uri https://graph.microsoft.com/v1.0/security/secureScores?$top=1 -Headers $Header -Method Get -ContentType 'application/json' -UseBasicParsing | Select -ExpandProperty Content) -match "\WcontrolName\W:\WBlockLegacyAuthentication\W,\Wdescription\W:.*?\Wscore\W:(\d+\.\d)"
    $maxscore = (Invoke-RestMethod -Uri https://graph.microsoft.com/v1.0/security/secureScoreControlProfiles -Headers $Header -Method GET -ContentType 'application/json').value | Select-Object id,maxScore | Where-Object {$_.id -eq "BlockLegacyAuthentication"} | Select -ExpandProperty maxScore
    if($Matches[1] -eq $maxscore){
        $scoresuccess.Add('1.1.6 Enable Conditional Access policies to block legacy authentication', 'Success with score : ' + $Matches[1] + ' and maxScore is : ' + $maxscore)
    }
    else{
        $scorefailed.Add('1.1.6 Enable Conditional Access policies to block legacy authentication', 'Failure with score : ' + $Matches[1] + ' and maxScore is : ' + $maxscore)
    }

    #1.2 ----------------------------------------------------------------------------------------

    $a = Get-OrganizationConfig | Select -ExpandProperty "OAuth2ClientProfileEnabled"
    if($a -eq $true ) {
        $scoresuccess.Add('1.2 Ensure modern authentication for Exchange Online is enabled', 'Success')
    }
    else{
        $scorefailed.Add('1.2 Ensure modern authentication for Exchange Online is enabled', 'Failure')
    }

    #1.3 ----------------------------------------------------------------------------------------

    $a = Get-CsOAuthConfiguration | Select -ExpandProperty ClientAdalAuthOverride
    if($a -eq "Allowed" ) {
        $scoresuccess.Add('1.3 Ensure modern authentication for Skype for Business Online is enabled','Success')
    }
    else {
        $scorefailed.Add('1.3 Ensure modern authentication for Skype for Business Online is enabled','Failure')
    }

    #1.4 ----------------------------------------------------------------------------------------
    
    if ( (Get-SPOTenant | Select -ExpandProperty LegacyAuthProtocolsEnabled ) -eq $false) {
        $scoresuccess.Add('1.4 Ensure modern authentication for SharePoint applications is required', 'Success')
    }
    else {
        $scorefailed.Add('1.4 Ensure modern authentication for SharePoint applications is required', 'Failure')
    }

    #1.5 ----------------------------------------------------------------------------------------
    
    if ((Get-MsolPasswordPolicy -DomainName mobicom.mn | Select -ExpandProperty "ValidityPeriod") -eq 2147483647 ){
        $scoresuccess.Add('1.5 Ensure that Office 365 Passwords Are Not Set to Expire', 'Success')
    }
    else {
        $scorefailed.Add('1.5 Ensure that Office 365 Passwords Are Not Set to Expire', 'Failure')
    }

}
AzureActiveDirectory
function ApplicationPermissions {

    #2.2 ----------------------------------------------------------------------------------------


    if ((Get-SharingPolicy | Where-Object { $_.Domains -like '*CalendarSharing*' } | Where-Object { $_.Enabled -like 'True'} | Select -ExpandProperty "Default") -eq $false ) {
        $scoresuccess.Add('2.2 Ensure calendar details sharing with external users is disabled', 'Success')
    }
    else {
        $scorefailed.Add('2.2 Ensure calendar details sharing with external users is disabled', 'Failure')
    }

    #2.3 ----------------------------------------------------------------------------------------

    if((Get-AtpPolicyForO365 | Select -ExpandProperty "AllowClickThrough") -eq $false -and (Get-AtpPolicyForO365 | Select -ExpandProperty "EnableSafeLinksForClients") -eq $true ){
        $scoresuccess.Add('2.3 Ensure O365 ATP SafeLinks for Office Applications is Enabled', 'Success')
    }
    else{
        $scorefailed.Add('2.3 Ensure O365 ATP SafeLinks for Office Applications is Enabled', 'Failure')
    }

    #2.4 ----------------------------------------------------------------------------------------

    if((Get-AtpPolicyForO365 | Select -ExpandProperty "EnableATPForSPOTeamsODB") -eq $true ){
        $scoresuccess.Add('2.4 Ensure Office 365 ATP for SharePoint, OneDrive, and Microsoft Teams is Enabled', 'Success')
    }
    else{
        $scorefailed.Add('2.4 Ensure Office 365 ATP for SharePoint, OneDrive, and Microsoft Teams is Enabled', 'Failure')
    }

}
ApplicationPermissions
function Datamanagement {
    
    #3.1 ----------------------------------------------------------------------------------------

    if((Get-OrganizationConfig |Select -ExpandProperty "CustomerLockBoxEnabled") -eq $true ){
        $scoresuccess.Add('3.1 Ensure the customer lockbox feature is enabled', 'Success')
    }
    else{
        $scorefailed.Add('3.1 Ensure the customer lockbox feature is enabled', 'Failure')
    }

    #3.4 ----------------------------------------------------------------------------------------

    (Invoke-WebRequest -Uri https://graph.microsoft.com/v1.0/security/secureScores?$top=1 -Headers $Header -Method Get -ContentType 'application/json' -UseBasicParsing | Select -ExpandProperty Content) -match "\WcontrolName\W:\WDLPEnabled\W,\Wdescription\W:.*?\Wscore\W:(\d+\.\d)"
    $maxscore = (Invoke-RestMethod -Uri https://graph.microsoft.com/v1.0/security/secureScoreControlProfiles -Headers $Header -Method GET -ContentType 'application/json').value | Select-Object id,maxScore | Where-Object {$_.id -eq "DLPEnabled"} | Select -ExpandProperty maxScore
    if($Matches[1] -eq $maxscore){
        $scoresuccess.Add('3.4 Ensure DLP policies are enabled', 'Success with score : ' + $Matches[1] + ' and maxScore is : ' + $maxscore)
    }
    else{
        $scorefailed.Add('3.4 Ensure DLP policies are enabled', 'Failure with score : ' + $Matches[1] + ' and maxScore is : ' + $maxscore)
    }

    #3.5 ----------------------------------------------------------------------------------------

    (Invoke-WebRequest -Uri https://graph.microsoft.com/v1.0/security/secureScores?$top=1 -Headers $Header -Method Get -ContentType 'application/json' -UseBasicParsing | Select -ExpandProperty Content) -match "\WcontrolName\W:\WDLPEnabled\W,\Wdescription\W:.*?\Wscore\W:(\d+\.\d)"
    $maxscore = (Invoke-RestMethod -Uri https://graph.microsoft.com/v1.0/security/secureScoreControlProfiles -Headers $Header -Method GET -ContentType 'application/json').value | Select-Object id,maxScore | Where-Object {$_.id -eq "DLPEnabled"} | Select -ExpandProperty maxScore
    if($Matches[1] -eq $maxscore){
        $scoresuccess.Add('3.4 Ensure DLP policies are enabled for Microsoft Teams', 'Success with score : ' + $Matches[1] + ' and maxScore is : ' + $maxscore)
    }
    else{
        $scorefailed.Add('3.4 Ensure DLP policies are enabled for Microsoft Teams', 'Failure with score : ' + $Matches[1] + ' and maxScore is : ' + $maxscore)
    }

    #3.6 ----------------------------------------------------------------------------------------
    
    if((Get-SPOTenant | Select -ExpandProperty "PreventExternalUsersFromResharing") -eq $true ){
        $scoresuccess.Add('3.6 Ensure that external users cannot share files, folders, and sites they do not own', 'Success')
    }
    else{
        $scorefailed.Add('3.6 Ensure that external users cannot share files, folders, and sites they do not own', 'Failure')
    }
}
Datamanagement
function EmailSecurity {
    
    #4.1 ----------------------------------------------------------------------------------------

    if((Get-MalwareFilterPolicy -Identity Default | Select -ExpandProperty "EnableFileFilter") -eq $true){
        $scoresuccess.Add('4.1 Ensure the Common Attachment Types Filter is enabled', 'Success')
    }
    else{
        $scorefailed.Add('4.1 Ensure the Common Attachment Types Filter is enabled', 'Failure')
    }

    #4.2 ----------------------------------------------------------------------------------------

    if((Get-HostedOutboundSpamFilterPolicy | Select -ExpandProperty "BccSuspiciousOutboundMail") -eq $true -and (Get-HostedOutboundSpamFilterPolicy | Select -ExpandProperty "NotifyOutboundSpam") -eq $true){
        $scoresuccess.Add('4.2 Ensure Exchange Online Spam Policies are set correctly', 'Success')
    }
    else{
        $scorefailed.Add('4.2 Ensure Exchange Online Spam Policies are set correctly', 'Failure')
    }

    #4.3 ----------------------------------------------------------------------------------------

    $a = Get-TransportRule | Where-Object {$_.RedirectMessageTo -ne $null}
    $b = $null -eq $a
    if($b -eq $true ){
        $scoresuccess.Add('4.3 Ensure mail transport rules do not forward email to external domains', 'Success')
    }
    else{
        $scorefailed.Add('4.3 Ensure mail transport rules do not forward email to external domains', 'Failure')
    }

    #4.4 ----------------------------------------------------------------------------------------

    $a = Get-TransportRule | Where-Object {($_.setscl -eq -1 -and $_.SenderDomainIs -ne $null)}
    $b = $null -eq $a
    if($b -eq $true ){
        $scoresuccess.Add('4.4 Ensure mail transport rules do not whitelist specific domains', 'Success')
    }
    else{
        $scorefailed.Add('4.4 Ensure mail transport rules do not whitelist specific domains', 'Failure')
    }

    #4.5 ----------------------------------------------------------------------------------------

    $a = Get-TransportRule | where { $_.Identity -like '*Client Rules To External Block*' }
    $b = $null -eq $a
    if($b -eq $true ){
        $scorefailed.Add('4.5 Ensure the Client Rules Forwarding Block is enabled', 'Failure')
    }
    else{
        $scoresuccess.Add('4.5 Ensure the Client Rules Forwarding Block is enabled', 'Success')
    }

    #4.6 ----------------------------------------------------------------------------------------

    if((Get-SafeLinksPolicy | Select -ExpandProperty "IsEnabled") -eq $true -and (Get-SafeLinksPolicy | Select -ExpandProperty "ScanUrls") -eq $true -and 
        (Get-SafeLinksPolicy | Select -ExpandProperty "AllowClickThrough") -eq $false) {
        $scoresuccess.Add('4.6 Ensure the Advanced Threat Protection Safe Links policy is enabled', 'Success')
    }
    else{
        $scorefailed.Add('4.6 Ensure the Advanced Threat Protection Safe Links policy is enabled', 'Failure')
    }

    #4.7 ----------------------------------------------------------------------------------------

    if((Get-SafeAttachmentPolicy | select -ExpandProperty "Enable") -eq $true){
        $scoresuccess.Add('4.7 Ensure the Advanced Threat Protection Safe Attachments policy is enabled', 'Success')
    }
    else{
        $scorefailed.Add('4.7 Ensure the Advanced Threat Protection Safe Attachments policy is enabled', 'Failure')
    }

    #4.8 ----------------------------------------------------------------------------------------

    $a = Get-OrganizationConfig | Select-Object -ExpandProperty DefaultAuthenticationPolicy | ForEach { Get-AuthenticationPolicy $_ | SelectObject AllowBasicAuth* }
    $b = $null -eq $a
    if($b -eq $true ){
        $scorefailed.Add('4.8 Ensure basic authentication for Exchange Online is disabled', 'Failure')
    }
    else{
        $scoresuccess.Add('4.8 Ensure basic authentication for Exchange Online is disabled', 'Success')
    }

    #4.9 ----------------------------------------------------------------------------------------

    $a = Get-AntiPhishPolicy | Select -ExpandProperty "Name"
    $b = $null -eq $a
    if($b -eq $true ){
        $scorefailed.Add('4.9 Ensure that an anti-phishing policy has been created ', 'Failure')
    }
    else{
        $scoresuccess.Add('4.9 Ensure that an anti-phishing policy has been created ', 'Success')
    }

    #4.10 ----------------------------------------------------------------------------------------
    
    if((Get-DkimSigningConfig | Select -ExpandProperty "Enabled") -eq $true){
        $scoresuccess.Add('4.10 Ensure that DKIM is enabled for all Exchange Online Domains', 'Success')
    }
    else{
        $scorefailed.Add('4.10 Ensure that DKIM is enabled for all Exchange Online Domains', 'Failure')
    }

    #4.13 ----------------------------------------------------------------------------------------

    if((Get-MalwareFilterPolicy | select -ExpandProperty EnableInternalSenderAdminNotifications) -eq $true){
        $scoresuccess.Add('4.13 Ensure notifications for internal users sending malware is Enabled', 'Success')
    }
    else{
        $scorefailed.Add('4.13 Ensure notifications for internal users sending malware is Enabled', 'Failure')
    }

    #4.14 ----------------------------------------------------------------------------------------

    if((Get-OrganizationConfig | Select -ExpandProperty "MailTipsAllTipsEnabled") -eq $true -and (Get-OrganizationConfig | Select -ExpandProperty "MailTipsExternalRecipientsTipsEnabled") -eq $true -and 
    (Get-OrganizationConfig | Select -ExpandProperty "MailTipsGroupMetricsEnabled") -eq $true -and (Get-OrganizationConfig | Select -ExpandProperty "MailTipsLargeAudienceThreshold") -eq 25 )
        {
        $scoresuccess.Add('4.14 Ensure MailTips are enabled for end users', 'Success')    
    }
    else{
        $scorefailed.Add('4.14 Ensure MailTips are enabled for end users', 'Failure')
    }
}
EmailSecurity
function Auditing{
    
    #5.1 ----------------------------------------------------------------------------------------

    if((Get-AdminAuditLogConfig | Select -ExpandProperty "AdminAuditLogEnabled") -eq $true -and (Get-AdminAuditLogConfig | Select -ExpandProperty "UnifiedAuditLogIngestionEnabled") -eq $true){
        $scoresuccess.Add('5.1 Ensure Microsoft 365 audit log search is Enabled', 'Success')
    }
    else{
        $scorefailed.Add('5.1 Ensure Microsoft 365 audit log search is Enabled', 'Failure')
    }

    #5.1 ----------------------------------------------------------------------------------------

    if((Get-Mailbox -ResultSize Unlimited -Filter {RecipientTypeDetails -eq "UserMailbox"} | Where-Object {($_.AuditEnabled -eq $false)}) -eq $null){
        $scoresuccess.Add('5.2 Ensure mailbox auditing for all users is Enabled', 'Success')
    }
    else{
        $scorefailed.Add('5.2 Ensure mailbox auditing for all users is Enabled', 'Failure') 
    }
}
Auditing
function Storage{
    
    #6.1 ----------------------------------------------------------------------------------------

    if((Get-SPOTenant | Select -ExpandProperty "SharingAllowedDomainList") -eq $null){
        $scorefailed.Add('6.1 Ensure document sharing is being controlled by domains with whitelist or blacklist', 'Failure')  
    }
    else{
        $scoresuccess.Add('6.1 Ensure document sharing is being controlled by domains with whitelist or blacklist', 'Success')
    }

    #6.2 ----------------------------------------------------------------------------------------

    if((Get-SPOTenantSyncClientRestriction | select -ExpandProperty TenantRestrictionEnabled) -eq $true){
        $scoresuccess.Add('6.2 Block OneDrive for Business sync from unmanaged devices', 'Success')
    }
    else{
        $scorefailed.Add('6.2 Block OneDrive for Business sync from unmanaged devices', 'Failure')
    }

    #6.3 ----------------------------------------------------------------------------------------

    if((Get-SPOTenant | select -ExpandProperty RequireAnonymousLinksExpireInDays) -eq 30){
        $scoresuccess.Add('6.3 Ensure expiration time for external sharing links is set', 'Success') 
    }
    else{
        $scorefailed.Add('6.3 Ensure expiration time for external sharing links is set', 'Failure')   
    }
}
Storage
$b = $scoresuccess.Count
$c = $scorefailed.Count
$a = $scoresuccess.Count + $scorefailed.Count
$spercent = (100 * $b)/$a
$fpercent = (100 * $c)/$a
$file1 = "$PSScriptRoot\success.json"
$file2 = "$PSScriptRoot\failed.json"
$file3 = "$PSScriptRoot\score.txt"
#$s1 = [math]::Round($spercent)
#$s2 = [math]::Round($ppercent)
$m = ([math]::Round($spercent)).ToString() + '% of CIS Benchmark configuration are configured properly. Please see detail from success.json and more information from https://www.cisecurity.org/cis-benchmarks/'
$m1 = ([math]::Round($fpercent)).ToString() + '% of CIS Benchmark configuration are not configured properly. Please see detail from failed.json and more information from https://www.cisecurity.org/cis-benchmarks/'
Add-Content -Path $file3 -Value $m
Add-Content -Path $file3 -Value $m1
$scoresuccess | ConvertTo-Json | set-content -Path $file1
$scorefailed | ConvertTo-Json | set-content -Path $file2