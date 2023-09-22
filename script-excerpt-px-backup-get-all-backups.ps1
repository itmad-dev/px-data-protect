<#
  REQUIREMENTS
    PSLogging PowerShell Module
     Install-Module PSLogging
    Accessible XML credentials file, with the password encrypted, containing Keycloak credentials
     e.g., "C:\[path]\[host]_credentials.xml"
    Acessible local configuration JSON file
     e.g., PX-BackupOperationsConfig.json
    Accessible logs location
     e.g., C:\[path]\logs
    Accessible script output location
     e.g., C:\[path]\output

.SYNOPSIS
List all backups found in all backup locations from a PX-Backup instance.

.DESCRIPTION
Sets Keycloak access token using PX-Backup login credentials, sends api request to list all backups in all backup locations.

.PARAMETER localConfigFile
Mandatory. The full path, file name to a JSON configuration file containing local environment specific variables for log and report paths, api endpoints/FQDNs, XML credentials file, and SMTP mail object details

.PARAMETER outputType
Mandatory. The report outut type: csv, html.

.NOTES
 Version 1.0
 Author:  Jerry Nihen
 Creation Date:  9/18/2023
 Purpose/change: initial creation
 Documentation:
   px-backup-rest-api-proc-rvw-doc-prj-01.docx
   https://github.com/itmad-dev/px-data-protect/px-backup-all-backups.ps1

.EXAMPLE
  [local path] .\px-backup-get-all-backups.ps1 -localConfigFile 'C:\scripts\config\PX-BackupOperationsConfig.json' -outputType 'csv'



#>

#------------------------------[Parameters]-----------------------------------
[CmdletBinding()]
param(
    [Parameter(Mandatory=$True, ParameterSetName="baseParams")]
    [String]$localConfigFile,
    [Parameter(Mandatory=$True, ParameterSetName="baseParams")]
    [ValidateSet('csv','html')]
    [String]$outputType
)
#------------------------------[Initializations]------------------------------


#------------------------------[Declarations]---------------------------------


#Date Time format
$script:strDate = (get-date).ToString("MMddyyyy_HHmm")

#Report components
$script:rptHeader = ''
$script:rptHeadingSummary = "<h3>PX-Backup Summary</h3>"
$script:rptHeadingSummaryFragments = ''
$script:rptFragments = ''
$script:rptFooter = ''

#Backups
$script:arrBackupsRawList = @()
$script:arrBackupsReportList = @()

#------------------------------[Functions]------------------------------
Function Set-ScriptVariablesFromLocalConfigFile(){
  Begin {
       
  }

  Process {
              
            $objConfigSettings = Get-Content -Path $localConfigFile | ConvertFrom-Json
            # credentials
            $script:creds = Import-Clixml -Path $objConfigSettings.credentials.credPathFile
            # logs
            $script:strLogPath = $objConfigSettings.logs.path
            $script:strLogFileNamePrelim = $objConfigSettings.logs.fileNamePrelim
            $script:strLogFileName = $script:strLogFileNamePrelim  + '_' + $strDate + '.txt'
            $script:strLogFile = Join-Path -Path $script:strLogPath -ChildPath $script:strLogFileName
            # reports
            $script:strReportPath = $objConfigSettings.reports.path
            $script:strReportFileNamePrelim = $objConfigSettings.reports.fileNamePrelim
            $script:strReportFileName = $script:strReportFileNamePrelim  + '_' + $strDate + '.' + $outputType
            $script:strReportFile = Join-Path -Path $script:strReportPath -ChildPath $script:strReportFileName
            # email
            $script:smtpServer = $objConfigSettings.email.smtpServer
            $script:smtpTo = $objConfigSettings.email.smtpTo
            $script:smtpFrom = $objConfigSettings.email.smtpFrom
            $script:smtpMessageSubject = $objConfigSettings.email.MessageSubject
            # pxBackupInstanceConfig
            $script:pxBackupHostClusterName = $objConfigSettings.pxBackupInstanceConfig.pxBackupHostClusterName
            $script:pxBackupUIUrl = $objConfigSettings.pxBackupInstanceConfig.pxBackupUIUrl
            $script:pxBackupRestApiEndpoint = $objConfigSettings.pxBackupInstanceConfig.pxBackupRestApiEndpoint
            $script:pxBackupRestApiPort = $objConfigSettings.pxBackupInstanceConfig.pxBackupRestApiPort
            $script:pxBackupOrganization = $objConfigSettings.pxBackupInstanceConfig.pxBackupOrganization
            # keycloakInstanceConfig
            $script:accessTokenRequestPath = $objConfigSettings.keycloakInstanceConfig.accessTokenRequestPath

   }

  End {
  }
  }

Function Set-AccessToken(){
  Begin {
  }

  Process {
        $accessTokenRequestURL = $pxBackupUIUrl + $script:accessTokenRequestPath 

$header = @{
  "Content-Type" = "application/x-www-form-urlencoded"
  "accept"       = "application/json"
 }

$body = @{grant_type='password'
      username=$script:creds.pxBackupCred.UserName
      password=$script:creds.pxBackupCred.GetNetworkCredential().password
      client_id='pxcentral'
}

        $script:accessTokenFullResponse = Invoke-RestMethod -Uri $accessTokenRequestURL -Body $body -Headers $header  -Method Post -Verbose
        $script:access_token = $script:accessTokenFullResponse.access_token

   }

  End {

  }
  }


Function Send-APIRequest{
    [CmdletBinding()]
    param (
        [string] $apiRequestDetails,
        [string] $accessToken
    )
  Begin {
  }

  Process {
            $header = @{
            "accept"        = "application/json"
            "Authorization" = "Bearer $accessToken"
        }
        $apiRequestURI = $script:pxBackupRestApiEndpoint + ":" + $script:pxBackupRestApiPort + $apiRequestDetails
        Invoke-RestMethod -Method GET -Uri $apiRequestURI -Headers $header
   
   }

  End {

  }
 }

 Function Get-Backups(){
  Begin {
  }

  Process {
         $apiRequestDetails = "/v1/backup/" + $script:pxBackupOrganization
        $arrBackupsRawList = Send-APIRequest -apiRequestDetails $apiRequestDetails -accessToken $script:access_token | Select-Object -ExpandProperty backups
        if ($arrBackupsRawList -ne $null) {
        foreach ($backup in $arrBackupsRawList) {
            $name = $backup.metadata.name.SubString(0,25) + "..."
            $created = $backup.metadata.create_time
            $jobStatus = $backup.backup_info.status.status
            $objBackup = New-Object PSObject -Property @{"Job name"=$name;"Created"=$created;"Job Status"=$jobStatus}
            $script:arrBackupsReportList += $objBackup
        }
        New-ReportSection('Backups')
        }
    
   }

  End {
  }
  }


Function New-ReportHeader(){
 Begin {

  }

  Process {
$script:rptHeader = @"
<style>
body {
font-family: "Trebuchet MS", Arial, Helvetica, sans-serif;
font-size: 10pt;
}
.boldRed {
 color: red;
 font-weight: bold;
}
.rptHdgSummary {
font-size: 11pt;
margin: 4px 0 0 4px;
}
.rptFooter {
 margin: 16px 0 0 0;
 font-weight: bold;
}
table {
border-collapse: collapse;
width:100%;
}
th {
padding-top: 8px;
padding-bottom: 8px;
padding-left: 4px;
text-align: left;
background-color: #ededed;
color: #FE5000;
}
td {border: .5px solid silver;padding-left: 4px;}
}
</style>
"@

   }

  End {
  }
  }

 Function New-ReportSection($sectHeading){
 Begin {
  }

  Process {
            switch ($sectHeading) 
            {
                'Backups' {
                    $script:rptFragments += $script:arrBackupsReportList | ConvertTo-Html -Property “Job name”, "Created", "Job status" -Fragment -PreContent "<h4>$sectHeading</h4>"  
                }
                default {
                    Write-LogInfo -LogPath $strLogFile -Message 'Invalid New Report Section'
                    Write-LogInfo -LogPath $strLogFile -Message ' '
                }
            }

   }

  End {

  }
  }

Function New-ReportFooter(){
 Begin {
  }

  Process {
$script:rptFooter = "<p class='rptFooter'>PX-Backup Summary - $script:pxBackupHostClusterName - generated on  $(Get-Date)</p>"

   }

  End {

  }
  }

 Function Group-ReportData($currOutputType){
 Begin {
  }

  Process {
              if ($script:arrBackupsReportList -ne $null)
            {
               switch ($currOutputType)
                  {
                    'csv' {
                        $script:arrBackupsReportList | Select “Job name”, "Created", "Job status"  | Export-Csv -Path $script:strReportFile -NoTypeInformation 
                    }
                    'html' {
                        $script:rptHeadingSummary += $script:rptHeadingSummaryFragments
                        $script:rptHeader += $script:rptHeadingSummary
                        ConvertTo-Html -Body $script:rptFragments -Title 'PX-Backup Summary' -Head $script:rptHeader -PostContent $script:rptFooter | Out-File $strReportFile
                    }

                     default { 'Unknown' }
                    }
           

            }else{
              Write-LogInfo -LogPath $script:strLogFile -Message 'Export-ReportData aborted.'
              Write-LogInfo -LogPath $script:strLogFile -Message ' '
            }

   }

  End {

  }
  }

Function Send-ReportDataEmail($currOutputType){
 Begin {
  }

  Process {
        if ([System.IO.File]::Exists($script:strReportFile))
        {
            $smtpServer = $script:smtpServer
            $smtpMessage = New-Object System.Net.Mail.MailMessage $script:smtpFrom, $script:smtpTo
            $smtpMessage.Subject = $script:smtpMessageSubject

             switch ($currOutputType)
              {
                'csv' {
                    $attReportFile = new-object System.Net.Mail.Attachment($script:strReportFile)
                    $smtpMessage.Attachments.Add($attReportFile)
                    $smtpMessage.Body = 'PX-Backups status' 
                }
                'html' {
                    $smtpMessage.IsBodyHTML = $true
                    $smtpMessage.Body = Get-Content $script:strReportFile -Raw 
                }
                 default { 'Unknown' }
                }
 
            $smtp = New-Object Net.Mail.SmtpClient($smtpServer)
            $smtp.UseDefaultCredentials = $false
            $smtp.Credentials = New-Object System.Net.NetworkCredential($creds.smtpCred.UserName, $creds.smtpCred.Password);
            $smtp.Send($smtpMessage)
        }else{
          Write-LogInfo -LogPath $script:strLogFile -Message 'Send-ReportDataEmail aborted.'
          Write-LogInfo -LogPath $script:strLogFile -Message ' '
        }

   }

  End {

  }
  }

#------------------------------[Execution]------------------------------

# Script setup settings
Set-ScriptVariablesFromLocalConfigFile
Set-AccessToken
# Backups
Get-Backups
# Report Prep, EMail
New-ReportHeader
# New-ReportHeadingSummary
New-ReportFooter
Group-ReportData $outputType
Send-ReportDataEmail $outputType
# Script teardown settings
Stop-Log -LogPath $strLogFile
Remove-Variable * -ErrorAction SilentlyContinue