#region Check Functions
function checkProfileSize
{

    #1.2 Profile size > 10GB
    $script:userProfileSize = (Get-ChildItem $env:USERPROFILE -Recurse -Force -EA SilentlyContinue | Measure-Object -Property length -Sum).Sum/1GB

    $output = New-Object PsObject -Property @{Status="" ; Message=""}

    if ($userProfileSize -lt 10)
    {
        $output.Status = "PASSED"
    }
    else
    {
        $output.Status = "FAILED"
        $output.Message = "Your Profile Size should be less than 10GB" # profile > 10GB
    }

    return $output

}

function checkProfileExists
{

    #1.1 User profile exists

    $output = New-Object PsObject -Property @{Status="" ; Message=""}

    if ($userProfileSize)
    {
	    $output.Status = "PASSED"
    }
    else
    {
	    $output.Status = "FAILED"
        $output.Message = "Unable to find your profile in D:\users" # profile > 10GB
    }

    return $output
}

function checknumberofFilesinProfile
{
    #Run "For /L %i in (1,1,41943) do fsutil file createnew A%i.tmp 204800 " in cmd prompt. This will create 8GB of 200KB files (41943 x 200KB files)
    # image creation failed with 8GB of 200KB files (42000) (amartini@ - It seems the threshold is around 10000)
    $script:numberOfFiles = ( Get-ChildItem $env:USERPROFILE | Measure-Object ).Count
    
    $output = New-Object PsObject -Property @{Status="" ; Message=""}

    #placeholder check but $max will need revising after testing the limit
    $script:max = "10000"
    if ($numberOfFiles -lt $max)
    {
        $output.Status = "PASSED"
    }
    else
    {
        $output.Status = "FAILED"
        $output.Message = "The number of files in your profile directory is too high.`n`n Your current count $numberOfFiles`nThe maximum allowed $max"
    }

    return $output

}

function checkTotalRequiredSpace
{
    #1.3 Free space on C drive (User profile size + 2GB additional)

    $output = New-Object PsObject -Property @{Status="" ; Message=""}

    $script:disk = ((Get-WmiObject Win32_LogicalDisk -Filter "DeviceID='C:'" | Select-Object FreeSpace).freespace)/1GB
    
    if ($userprofilesize+2 -lt $disk)
    {
        $output.Status = "PASSED"
    }
    else
    {
        $output.Status = "FAILED"
        $output.Message = "You do not have enough storage space left on your C: drive for image creation`n`nPlease make more space available and rerun the test"
    }

    return $output
}

function checkLongPathName
{
    $script:longpathlist = @()
    #1.4 Long path name (256 character limit) for C:\users\%username%

    $output = New-Object PsObject -Property @{Status="" ; Message=""}

    $script:testCdrive = cmd /c dir "C:\users" /s /b |? {$_.length -gt 256}
    $script:testDdrive = cmd /c dir "D:\users" /s /b |? {$_.length -gt 256}

    if ($testCdrive)
    {
        $longpathlist += $testCdrive
        $output.Status = "FAILED"
        $output.Message += "One of your folder/directory path name is too long.`n`nThe path is $longPathList"
    }
    elseif ($testDdrive)
    {
        $longpathlist += $testDdrive
        $output.Status = "FAILED"
        $output.Message += "One of your folder/directory path name is too long.`n`nThe path is $longPathList"
    }
    else
    {
        $output.Status = "PASSED"
    }

    return $output

}

function checkServicesLocalSystemAccount
{
    $serviceList = @()
    #1.5 No application services that use domain user credentials can be running on the WorkSpace when the image is created. For example, you cannot have a Microsoft SQL Server Express installation running with a domain userâ€™s credentials when you create the image. You must use a local system account instead.
    $script:Services = Get-WmiObject -Class Win32_service | Select Name, StartName
    
    $output = New-Object PsObject -Property @{Status="" ; Message=""}

    foreach ($service in $Services)
    {
        if (($service.StartName -eq "LocalSystem") -or ($service.StartName -eq "NT AUTHORITY\LocalService") -or ($service.StartName -eq "NT AUTHORITY\NetworkService"))
        {
            $output.Status = "PASSED"
        }
        else
        {
            $script:serviceList += $service.name
            $output.Status = "FAILED"
            $output.Message = "Services not running with local System Accounts were detected`n`n"
        }
    }

    if($output.Status -eq "FAILED"){

        $output.Message += $serviceList

    }

    return $output
}

function checkPendingUpdates
{
    $path1 = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired'
    $path2 = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending' # doesnt work for 2003

    $output = New-Object PsObject -Property @{Status="" ; Message=""}
    
    if (test-path $path1 -ErrorAction SilentlyContinue)
    {
        $output.Status = "FAILED"
        $output.Message = "Please reboot to finish installing pending Windows/Software updates."
    }
    elseif (test-path $path2 -ErrorAction SilentlyContinue)
    {
        $output.Status = "FAILED"
        $output.Message = "Please reboot to finish installing pending Windows/Software updates."
    }
    else
    {
        $output.Status = "PASSED"
    }

    return $output
}

function checkUnsupportedSysprepRoles
{
    $roleList = @(
    "Active Directory Certificate Services",`
    "Active Directory Domain Services",`
    "Active Directory Federation Services",`
    "Active Directory Lightweight Directory Services",`
    "Active Directory Rights Management Services",`
    "DHCP Server",`
    "Fax Server",`
    "Network Policy and Access Services",`
    "Windows Deployment Services",`
    "Windows Server Update Services"
    )

    # ref https://technet.microsoft.com/en-us/library/hh824835.aspx?f=255&MSPPError=-2147217396
    $installedRoles = Get-WindowsFeature | ?{$_.featuretype -eq "Role" -and $_.installed -eq $true}

    $matches = @()

    $output = New-Object PsObject -Property @{Status="" ; Message=""}
    $output.Status = "PASSED"

    foreach ($role in $installedRoles)
    {
        if ($role.DisplayName -in $roleList)
        {
            $matches += $role.DisplayName
            $output.Status = "FAILED"
        }

    }
    
    if($output.Status -eq "FAILED"){

        $output.Message = "Installed roles not supported by Sysprep were detected:`n`n$matches`n`n`See: https://technet.microsoft.com/en-us/library/hh824835.aspx?f=255&MSPPError=-2147217396"

    }

    return $output
}

function checkInstalledSoftware
{

    Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | `
    Select-Object DisplayName, InstallLocation | `
    ? {$_.DisplayName -notlike "Microsoft .NET Framework*" `
    -and $_.DisplayName -notlike "Microsoft Visual C++*" `
    -and $_.DisplayName -notlike "Microsoft Office*" `
    -and $_.DisplayName -notlike "NVIDIA*" `
    -and $_.DisplayName -notlike "CVE-*" `
    -and $_.DisplayName -notlike "PCoIP Agent*" `
    -and $_.DisplayName -notlike "EC2ConfigService*" `
    -and $_.DisplayName -notlike "EC2ConfigService*" `
    -and $_.DisplayName -notlike "WinZip*" `
    -and $_.DisplayName -notlike "aws-cfn*"} | `
    Format-Table –AutoSize

}

Function getCallDepth()
{
    param 
    (
        [string]$rootRegistryKey,
        [int]$currentCallDepth
    )
	$maxDetails = ($currentCallDepth, $rootRegistryKey, $true)
	
	foreach ($subKey in Get-ChildItem -literalPath $rootRegistryKey -Force -ErrorAction SilentlyContinue)
    {
	  try
	  { 
	    $callDetails = getCallDepth $subKey.PSPath ($currentCallDepth+1)

		if ($maxDetails[0] -lt $callDetails[0])
		{
		  $maxDetails = $callDetails
		}
		
		if ($callDetails[2] -eq $false)
		{
		  break
		}
	  }
	  catch [exception]
      {

		$maxDetails = ($maxDetails[0], $maxDetails[1], $false)

        return $maxDetails

      }
    }
	
	return $maxDetails
}

function getCallDepthCurrentUser()
{
    param 
    (
        [string]$rootRegistryKey
    )

    $maxCallDepth = getCallDepth $rootRegistryKey 1
	
	return $maxCallDepth

}

function checkDeeplyNestedRegKeys
{

    $output = New-Object PsObject -Property @{Status="" ; Message=""}
    
    $rootRegistryKey = "HKCU:"
    $result = GetCallDepthCurrentUser $rootRegistryKey

	if($result[2]){

      $output.Status = "PASSED"

    }
    else{

       $output.Status = "FAILED"
       $output.Message = "A Registry key that is too deeply nested was found under:`n`n{0} `n`nDepth: {1}" -f $result[1], $result[0]

    }

    return $output
}

function checkIsWAMInstalled
{
    $script:WAM = get-itemproperty -path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*" | ? {$_.displayname -like "Amazon WorkSpaces Application Manager"}

    $output = New-Object PsObject -Property @{Status="" ; Message=""}

    if ($WAM)
    {
        $output.Status = "FAILED"
        $output.Message = "WorkSpaces Application Manager is currently installed`n`nIf you want to use Amazon WAM with Amazon WorkSpaces created from custom images, don't launch the Amazon WAM client in the WorkSpace that is used to create the custom image. This ensures that the WorkSpaces you launch from the custom image you create won't have any Amazon WAM configuration tied to the WorkSpace where you originally created the image"
    }
    else
    {
        $output.Status = "PASSED"
    }

    return $output

}

#endregion Check Functions

#region GUI
function clearOutputBox
{
    $OutputBox.clear()
}

function Button_Click()
{

    clearOutputBox
    
    #place holder text
    $outputBox.AppendText("Running Tests... This could take a few minutes to complete")

    $checkNumber = 0

    foreach($check in $script:checks){

        $results[$checkNumber].ForeColor = "Green"
        $results[$checkNumber].Text = "Checking..."
        $result = Invoke-Expression $check
        
        switch($result.Status)
        {
            PASSED
            {
                $script:results[$checkNumber].ForeColor = "Green"
                $script:results[$checkNumber].Text = $result.Status
            }
            FAILED
            {
                $script:results[$checkNumber].ForeColor = "Red"
                $script:results[$checkNumber].Text = $result.Status
            
                $script:troubleButtons[$checkNumber].Visible = $true
                $script:troubleButtons[$checkNumber].Name = $result.Message
                $script:troubleButtons[$checkNumber].Add_Click(
                    {
                        clearOutputBox
                        $outputBox.AppendText($this.Name)
                    }
                )
            }
            Default{$outputBox.AppendText("Unable to return results")}
        }

        $checkNumber += 1
        $script:progressBar.value += 100*1/$script:checks.Count

    }

    clearOutputBox
    $OutputBox.AppendText("Finished running all checks")
    
    $summary = ""

    for($i=0; $i -lt $script:checks.Count; $i++){

        if($script:results[$i].Text -eq "FAILED"){

            $summary += $script:checkDescriptions[$i] + "`n"

        }

    }

    $OutputBox.AppendText("`nFAILED CHECKS:`n`n" + $summary)

}

# - Form Section


Function Generate-Form {

    Add-Type -AssemblyName System.Windows.Forms    
    Add-Type -AssemblyName System.Drawing
    
    # Build Form
    $Form = New-Object System.Windows.Forms.Form
    $Form.Text = "Workspace Image Checker"
    $Form.Size = New-Object System.Drawing.Size(500,580)
    $Form.MaximizeBox = $disable
    $form.MinimizeBox = $disable
    $form.FormBorderStyle = "FixedDialog"
    $Form.StartPosition = "WindowsDefaultLocation"
    $Form.Topmost = $True
    $Form.ShowInTaskbar = $True
   
    #~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    # Test Labels 


    # Layout
    $pos1X = 40 # First column
    $pos2X = 320 # Second column
    $pos3X = 395 # Third column
    $posY = 100
    $incrementY = 25

    # Button sizes
    $buttonWidth = 50
    $buttonHeight = 20

    $script:results = @()
    $script:troubleButtons = @()

    for($i=0;$i -lt $script:checks.Count; $i++){

        # Labels 
        $label = New-Object System.Windows.Forms.label
        $label.Location = New-Object System.Drawing.Size($pos1X,$posY)
        $label.Text = $script:checkDescriptions[$i]
        $label.AutoSize = $true

        $result = New-Object System.Windows.Forms.label
        $result.Location = New-Object System.Drawing.Size($pos2X,$posY)
        $result.Text = "N/A"
        $result.AutoSize = $True

        # Buttons
        $troubleButton = New-Object System.Windows.Forms.Button
        $troubleButton.Location = New-Object System.Drawing.Size($pos3X,$posY)
        $troubleButton.Size = New-Object System.Drawing.Size($buttonWidth,$buttonHeight)
        $troubleButton.Text = "why ?"
        $troubleButton.Visible = $false

        $Form.Controls.Add($label)
        $Form.Controls.Add($result)
        $Form.Controls.Add($troubleButton)

        $script:results += $result
        $script:troubleButtons += $troubleButton

        $posY += $incrementY

    }

    #~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    # Additional big buttons and progress bar

    #Add big buttons
    $Button1 = New-Object System.Windows.Forms.Button
    $Button1.Location = New-Object System.Drawing.Size(50,20)
    $Button1.Size = New-Object System.Drawing.Size(120,50)
    $Button1.Text = "Check Prerequisites"
    
    $progressBarLabel = New-Object System.Windows.Forms.label
    $progressBarLabel.Location = New-Object System.Drawing.Size(310,20)
    $progressBarLabel.AutoSize = $True
    $progressBarLabel.Text = "Progress Bar"
        
    $script:progressBar = New-Object System.Windows.Forms.ProgressBar
    $script:progressBar.Value = 0
    $script:progressBar.Style="Continuous"
    $script:progressBar.Location = New-Object System.Drawing.Size(250,40)
    $script:progressBar.Size = New-Object System.Drawing.Size(200,30)
   
    #Add big buttons to form
    $Form.Controls.Add($Button1)
    $Form.Controls.Add($progressBarLabel)
    $Form.Controls.Add($script:progressBar)
    
    #Add Button event 
    $Button1.Add_Click({Button_Click})


    # Big buttons
    #~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    #~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    # Output Box

    $OutputBox = New-Object System.Windows.Forms.RichTextBox
    $OutputBox.Location = New-Object System.Drawing.Size(50,380)
    $OutputBox.Size = New-Object System.Drawing.Size(400,100)
    $Form.Controls.Add($OutputBox)

    #~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    # Output Box

    #Add Link labels
    $LinkLabel1 = New-Object System.Windows.Forms.LinkLabel 
    $LinkLabel1.Location = New-Object System.Drawing.Size(50,500) 
    $LinkLabel1.AutoSize = $True
    $LinkLabel1.LinkColor = "BLUE" 
    $LinkLabel1.ActiveLinkColor = "RED" 
    $LinkLabel1.Text = "WorkSpace Image Management Guide" 
    $LinkLabel1.add_Click({[system.Diagnostics.Process]::start("http://docs.aws.amazon.com/workspaces/latest/adminguide/images.html")}) 
    

    $LinkLabel2 = New-Object System.Windows.Forms.LinkLabel 
    $LinkLabel2.Location = New-Object System.Drawing.Size(50,520) 
    $LinkLabel2.AutoSize = $True
    $LinkLabel2.LinkColor = "BLUE" 
    $LinkLabel2.ActiveLinkColor = "RED" 
    $LinkLabel2.Text = "WorkSpace Bundle Management Guide" 
    $LinkLabel2.add_Click({[system.Diagnostics.Process]::start("http://docs.aws.amazon.com/workspaces/latest/adminguide/bundles.html")}) 
    
    #Add link labels to form
    
    $Form.Controls.Add($LinkLabel1) 
    $Form.Controls.Add($LinkLabel2)
    
    #Show the Form (do this at the end of the function)
    $form.ShowDialog()| Out-Null 
}

#endregion GUI

$script:checks = @("checkProfileSize",`                "checkProfileExists",`                "checknumberofFilesinProfile",`                "checkTotalRequiredSpace",`                "checkLongPathName",`                "checkServicesLocalSystemAccount",`                "checkPendingUpdates",`                "checkUnsupportedSysprepRoles",`                "checkDeeplyNestedRegKeys",`                "checkIsWAMInstalled"                )
$script:checkDescriptions = @("Profile Size < 10GB",`                "Profile Exists on D:\",`                "High number of files in Profile",`                "Sufficient space left on C:\",`                "Folder Path Name > 260 char",`                "Services with local system accounts",`                "Pending Software/Windows Updates",`                "Unsupported roles for Sysprep",`                "Deeply nested Registry Keys",`                "WAM currently installed"                )

Generate-Form
