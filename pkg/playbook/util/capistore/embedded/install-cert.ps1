 <##################
.DESCRIPTION
    install-cert adds or verifies an end-entity certificate is installed in the Personal CAPI store
.PARAMETER certBytes
    The path of a PKCS#12 which contains the end-entity certificate and private key
.PARAMETER friendlyName
    A text string that is used to identify the certificate when extracting it from the CAPI store
.PARAMETER isNonExportable
    A boolean that controls whether or not the certificate should be exportable after it has been installed into the CAPI store
.PARAMETER password
    The string password that was used to encrypt the private key
.PARAMETER certStore
    The location to store the certificate in CAPI
##################>
function install-cert {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string] $friendlyName,

        [Parameter(Mandatory)]
        [string] $storeName,

        [Parameter(Mandatory)]
        [System.Security.Cryptography.X509Certificates.storeLocation] $storeLocation,

        [Parameter(Mandatory)]
        [bool] $isNonExportable,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string] $password,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [ValidateScript( {
            if (Test-Path -Path $_) {
                $true
            } else {
                throw "unable to read PFX from '$($_)'"
            }
        })]
        [string] $certPath
    )

    # Make the keyset accessible only to user when installing in CurrentUser
    $keyset = if ($storeLocation -eq [System.Security.Cryptography.X509Certificates.StoreLocation]::CurrentUser) {'UserKeySet'} else {'MachineKeyset'}
    $exportable = if (-not $isNonExportable) { 'Exportable,' }
    
    $collection = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2Collection
    $collection.Import($certPath, $password, "$($exportable)$($keyset),PersistKeySet")

    foreach ($cert in $collection.GetEnumerator())
    {
        # The storeName changes based on certificate type. Defaults to the specified store where the end-entity cert will go.
        #  use installToStore so not to reset the global $storeName variable
        $installToStore = $storeName
        
        $is_ca_cert = $false
        foreach ($ext in $cert.Extensions)
        {
            if ($ext.GetType().Name -eq "X509BasicConstraintsExtension")
            {
                $is_ca_cert = $ext.CertificateAuthority
                break
            }
        }

        if ($is_ca_cert)
        {
            # check to see if it is a root certificate
            if ($cert.Issuer -eq $cert.Subject)
            {
                $installToStore = "Root"
                if (Test-Path "Cert:\$($storeLocation)\$($installToStore)\$($cert.Thumbprint)")
                {
                    continue  # already in the CAPI store
                }
            }
            else # it is an intermediate certificate
            {
                $installToStore = "CA"
                if (Test-Path "Cert:\$($storeLocation)\$($installToStore)\$($cert.Thumbprint)")
                {
                    continue  # already in the CAPI store
                }
            }
        }
        else
        {
            if (!(Test-Path "Cert:\$($storeLocation)\$($installToStore)\$($cert.Thumbprint)"))
            {
                $cert.FriendlyName = $friendlyName
            }
            else
            {
                $existing = Get-Item "Cert:\$($storeLocation)\$($installToStore)\$($cert.Thumbprint)"

                if ($existing.FriendlyName -ne $friendlyName)
                {
                    throw "Certificate already installed but FriendlyName does not match - $($existing.FriendlyName)"
                }

                continue
            }
        }

        $capi = Get-Item "Cert:\$($storeLocation)\$($installToStore)"
        $capi.Open("ReadWrite")
        $capi.Add($cert)
        $capi.Close()

        # wait two seconds before checking to see the installation was successful
        Start-Sleep -s 2

        if (!(Test-Path "Cert:\$($storeLocation)\$($installToStore)\$($cert.Thumbprint)"))
        {
            if ($is_ca_cert) {
                throw "Failed to install chain certificate on target system - $($cert.Subject)"
            }
            else
            {
                throw "Could not install certificate on target system"
            }
        }
    }
}
