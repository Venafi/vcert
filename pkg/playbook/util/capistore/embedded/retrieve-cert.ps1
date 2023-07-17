<##################
.DESCRIPTION
    retrieve-cert verifies an end-entity certificate is installed in the Personal CAPI store and saves it to a file
.PARAMETER friendlyName
    A text string that is used to identify the certificate when extracting it from the CAPI store
.PARAMETER certStore
    The location to store the certificate in CAPI
 #>
##################>
Set-StrictMode -Version Latest

function retrieve-cert {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string] $friendlyName,
        [Parameter(Mandatory)]
        [System.Security.Cryptography.X509Certificates.storeName] $storeName,
        [Parameter(Mandatory)]
        [System.Security.Cryptography.X509Certificates.storeLocation] $storeLocation
    )
    # Get the certificate store
    $store = New-Object System.Security.Cryptography.X509Certificates.X509Store($storeName, $storeLocation)
    $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadOnly)

    # Find unexpired certificates by friendly name
    $certs = $store.Certificates | Where-Object { ($_.FriendlyName -eq $friendlyName) -and ($_.NotAfter -gt (Get-Date)) } 

    # Close the certificate store
    $store.Close()
    
    # If there is more than one cert with this friendly name, get the one expiring furthest in the future
    $cert = $null
    if ($null -ne $certs) {
        $cert = ($certs | Sort-Object -Descending -Property 'NotAfter')[0]
    }
    
    # Save the certificate to a file
    if ($null -ne $cert) {
        $certBytes = $cert.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert)
        $base64Cert = [System.Convert]::ToBase64String($certBytes)
        $certPem = "-----BEGIN CERTIFICATE-----`n" + ($base64Cert -replace "(.{64})", "`$1`n") + "`n-----END CERTIFICATE-----`n"
        Write-Output -InputObject $certPem
    } else {
        Write-Output -InputObject "certificate not found: $($friendlyName)"
    }
}