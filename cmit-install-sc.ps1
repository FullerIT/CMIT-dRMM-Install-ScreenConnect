<# cmit-install-sc.ps1
pellis@cmitsolutions.com
2025-06-20-001

This tries to fix the changes that resulted from the software changes ConnectWise had to apply to Screenconnect on this release: 
https://docs.connectwise.com/ScreenConnect_Documentation/ScreenConnect_release_notes/ScreenConnect_2025.4_Release_notes

The certificate verification doesn't work with msi files, it would need to be redesigned but I'm not sure why checking that matters, it's a nice to have, but not critical.

dRMM Variables:
ConnectWiseControlPublicKeyThumbprint [string]
usrUDF [string]
ConnectWiseControlBaseUrl [string]

#>

#debug vars
#$env:ConnectWiseControlPublicKeyThumbprint = "0ba9066856b8518d"
#$env:usrUDF = "1"
#$env:ConnectWiseControlBaseUrl = "https://cmitcincy.screenconnect.com"
#$env:CS_PROFILE_NAME = "CMIT Solutions of Cincinnati & NKY"

#function provided by Datto
function verifyPackage ($file, $certificate, $thumbprint, $name, $url) {
    $varChain = New-Object -TypeName System.Security.Cryptography.X509Certificates.X509Chain
    try {
        $varChain.Build((Get-AuthenticodeSignature -FilePath "$file").SignerCertificate) | out-null
    } catch [System.Management.Automation.MethodInvocationException] {
        write-host "- ERROR: $name installer did not contain a valid digital certificate."
        write-host "  This could suggest a change in the way $name is packaged; it could"
        write-host "  also suggest tampering in the connection chain."
        write-host "- Please ensure $url is whitelisted and try again."
       write-host "  If this issue persists across different devices, please file a support ticket."
    }

    $varIntermediate=($varChain.ChainElements | ForEach-Object {$_.Certificate} | Where-Object {$_.Subject -match "$certificate"}).Thumbprint

    if ($varIntermediate -ne $thumbprint) {
        write-host "- ERROR: $file did not pass verification checks for its digital signature."
        write-host "  This could suggest that the certificate used to sign the $name installer"
        write-host "  has changed; it could also suggest tampering in the connection chain."
        write-host `r
        if ($varIntermediate) {
            write-host ": We received: $varIntermediate"
            write-host "  We expected: $thumbprint"
            write-host "  Please report this issue."
        } else {
            write-host "  The installer's certificate authority has changed."
        }
        write-host "- Installation cannot continue. Exiting."
        exit 1
    } else {
        write-host "- Digital Signature verification passed."
    }
}

function CreateJoinLink {
    $null = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\ScreenConnect Client ($env:ConnectWiseControlPublicKeyThumbprint)" -Name ImagePath).ImagePath -Match '(&s=[a-f0-9\-]*)'
    $GUID = $Matches[0] -replace '&s='
    #$apiLaunchUrl= "$($env:ConnectWiseControlBaseUrl)" + "/Host#Access///" + $GUID + "/" + $GUID + "/Join"
    #Example: https://cmitcincy.screenconnect.com/Host#Access/All%20Machines/5c00013c-c216-48df-b256-262b63790e7c/5c00013c-c216-48df-b256-262b63790e7c/General
    $apiLaunchUrl= "$($env:ConnectWiseControlBaseUrl)" + "/Host#Access/All%20Machines/" + $GUID + "/" + $GUID + "/Join"
    New-ItemProperty -Path "HKLM:\Software\CentraStage" -Name "Custom$env:usrUDF" -PropertyType String -Value $apiLaunchUrl -force | out-null
    write-host "- UDF written to UDF#$env:usrUDF."
}

if (Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\ScreenConnect Client ($env:ConnectWiseControlPublicKeyThumbprint)" ) {
    write-host "- ConnectWise Control already installed. Establishing link..."
    CreateJoinLink
} else {
    $company = $env:CS_PROFILE_NAME
    $company = $company.TrimEnd()
    $company = [uri]::EscapeDataString($company)
    $insturl = $env:ConnectWiseControlBaseUrl + "/Bin/ScreenConnect.ClientSetup.msi?e=Access&y=Guest&c=" + $company + "&c=&c=&c=&c=&c=&c="
    $tmp = "ScreenConnect.ClientSetup.msi"
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    Invoke-WebRequest -Uri $insturl -OutFile $tmp
    #cert from 16/August/2022 to 15/August/2025
    #verifyPackage $tmp "ConnectWise, LLC" "4c2272fba7a7380f55e2a424e9e624aee1c14579" "ConnectWise Control Client Setup" $insturl
    write-host "- Installing ConnectWise Control..."
    Start-Process -Wait -FilePath "msiexec.exe" -ArgumentList "/i $tmp /qn" -PassThru
    CreateJoinLink
}