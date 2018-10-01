/*
 * Copyright 2018 Venafi, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package certificate

import (
	"crypto/x509"
	"encoding/pem"
	"strings"
	"testing"
)

var pkPEM = `-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-256-CBC,e6fd60eaab2166aa498479b0eb947d21
pkormg5NbGtPPnLg58JAS10jUaRPJVPZKD6OkCabW9C3FVKhg7y2jaJ3VnNPEDXI
TwnZwl3oX0MXuCrN15ryoZBKQsxewnprOQ5c9FcoSPCSafFZ8RWfZoirCdap2uRB
Au5oLg7waK9ESe50xTdiAkRVm+4F3+k6TOygJ19i1Gr8mp+xD8J3CntLSjF7JgTC
JBBOrD5FjYHDzgG7wRtc3QpRlqAehN2RSZSYLkO5D/qoq1i1EW5CbBh8v748MXFv
Hol8tpygZS+ZCVJGbxsNRyjhpFArG1yZEcYtU4XDqcWvxVlJc8scCZHw3elhHekz
bH7kuTEm59oeeKjKyfsBt8SmPvxgvw1phT06y1D5xVslTZl7GuRARBDI/B5a5bBJ
XjTd39VCq6NuX2NrOVTo6h2zJL4sXEs6Yz1vhb9PfA8ROswAGDceUWMUc0yhsxVh
ihdDazqQiMnj6+MV/mRlEDPfur2Gs9ia0RMogrnJF+lHk3a8zw75Pa9F9G7ZQivo
SRIUd7QcBS28Vpe2pPrsigdzRiBz+g48gSN/2qozZ3lg4DK6m3uWWQK6qrkSd2nm
z/LX3BZKp4oCLY2ka/3bX9nKt9n9U4Sg1yCMVQpiugPFN9zAJew6Go40AbGIK34U
7hpPUSKhF4NYCNR1DuLWPx9RbXUndx3tYOwJzfu7f47XBxrOyqOGl5eWXU/KDyJs
rIhySi1xSTJKAKXk5+8pi9YfmcixQXsGnzR1aRaw1D3ochcUWYXe/44EBB4bK2Mi
MJBAposdOW8bONwKcQXFLXtUUkW3JfdzY+61OEuo647FtYPRPUMphIoEWuTiUPWj
XsTOXPpxew0hjd3LROueL3kQ+PuuMubdAdKj44ej4eXYKAyKPQx75jTczPYiiRah
/Eu+iiyTwfJhWiTX5WE5luQ0KGCx2Th3RgtrvaPTO+PrEQ+xVQnvkupS0XdA4Um1
HGosjPP3TDdfomVmrazfPUzX3en23xJ+9DIgSxfP0dfbBNZQqVI31A1MN4oBbm1k
iMXXOaKwwgChVwrB5F1XGEviKt5YU1l4SD+Bhqe37gJ/+NtnMo/PAdODnVRQOSV7
Oqnh5m2ZYOJN2SWcPS0hnsLsc0a9tsiY6MIj7+Lsfx2b7I4NB2NFLFWVVOfXNc49
DdVfl4Eqcbox/IpTYwMpdUnVaCb4zukiB66Vxs/+SSGqmKrFO6aObtLudcH2MhlK
Wg+QGH1A8W9keoHha+dhW9nwlLNncx9YP4ZwKMTNavUzxv8Mu1LQcLs4BZt3I/mq
wrL3sZVWnr4wh0QOPpBtQ2Bhratdswkg6bcWA7eUJpzCD/C4/lKOX60ZNpoU7G7Q
BJtvLnNbJB4j2iKsoip2spftb5iTFz3Fq5Q9g7BEQIjb5CJtwuWBDg/ZVhP2GD8m
884Hxp7atHRqz4COW3CV7NYX0HVJzYgZJnS9BpGAAa+TyvVUSwJhUHJJdgCRgfho
LGi5abZWRQkSmrWZzxqw/TGMHwvi6xUxQnyWvr35uQmtE9LT8e02iNP0Ukz3HCDX
aKzB+IbTjVJZfd/UWzS4/KrXpUwnQCnidTirXM+D7iX9rOH6EfeQ0TMWaYL1ZSX3
-----END RSA PRIVATE KEY-----`

// Subject: C=US, ST=Utah, L=SLC, O=Venafi, Inc., OU=Engineering, OU=Quality Assurance, CN=certafi-bonjo.venafi.com
var certPEM = `-----BEGIN CERTIFICATE-----
MIIGmjCCBYKgAwIBAgIKVHuFEgABAABQyjANBgkqhkiG9w0BAQUFADBfMRMwEQYK
CZImiZPyLGQBGRYDY29tMRYwFAYKCZImiZPyLGQBGRYGdmVuYWZpMRUwEwYKCZIm
iZPyLGQBGRYFdmVucWExGTAXBgNVBAMTEFZlblFBIENsYXNzIEcgQ0EwHhcNMTYw
MjI2MTk0NzMwWhcNMTYwMzAyMTk0NzMwWjCBljELMAkGA1UEBhMCVVMxDTALBgNV
BAgTBFV0YWgxDDAKBgNVBAcTA1NMQzEVMBMGA1UEChMMVmVuYWZpLCBJbmMuMRQw
EgYDVQQLEwtFbmdpbmVlcmluZzEaMBgGA1UECxMRUXVhbGl0eSBBc3N1cmFuY2Ux
ITAfBgNVBAMTGGNlcnRhZmktYm9uam8udmVuYWZpLmNvbTCCASIwDQYJKoZIhvcN
AQEBBQADggEPADCCAQoCggEBAN0E7Ez+UNB0gQa1YS25L/uQuacQkNva6RvAexRO
5ow9mZBRVbfYP/K3vvFgJpebUFuvyctidkco422dkWRFjX+6tTl2tgU9vFySkMg1
dP9Cy2LdiSibQf+SmqOTkeH0rgjQSOxUepHCdPP4FwfQV5J7SZEYPVTZ8AOBfyON
0ZxOjcw3RlT1EaJ0bBQM801J90F5KSvoEW8IL3Ttu4pYLSeb8KX5+xbJs6deQTSq
TDWIGxl+xvZLwcJwDXTWqOsx2XyynjfCTL/Ox/QkSSsLnRP0oG4xdW1Kkk8v4hef
6Zz/8nK7aJhR2aqybOjYBGFp61fXREUqJufjWKuzj0IgNEkCAwEAAaOCAx4wggMa
MB0GA1UdDgQWBBRHyE5rv1Il20ys6I5zblqwiPeNrzAfBgNVHSMEGDAWgBTzfiJW
xHk+5FI7Rch+opVcolhaeDCBsAYDVR0fBIGoMIGlMIGioIGfoIGchk9odHRwOi8v
dmVucWEtMms4LWljYTEudmVucWEudmVuYWZpLmNvbS9DZXJ0RW5yb2xsL1ZlblFB
JTIwQ2xhc3MlMjBHJTIwQ0EoMSkuY3JshklmaWxlOi8vVmVuUUEtMms4LUlDQTEu
dmVucWEudmVuYWZpLmNvbS9DZXJ0RW5yb2xsL1ZlblFBIENsYXNzIEcgQ0EoMSku
Y3JsMIIBggYIKwYBBQUHAQEEggF0MIIBcDCBvQYIKwYBBQUHMAKGgbBsZGFwOi8v
L0NOPVZlblFBJTIwQ2xhc3MlMjBHJTIwQ0EsQ049QUlBLENOPVB1YmxpYyUyMEtl
eSUyMFNlcnZpY2VzLENOPVNlcnZpY2VzLENOPUNvbmZpZ3VyYXRpb24sREM9dmVu
cWEsREM9dmVuYWZpLERDPWNvbT9jQUNlcnRpZmljYXRlP2Jhc2U/b2JqZWN0Q2xh
c3M9Y2VydGlmaWNhdGlvbkF1dGhvcml0eTB1BggrBgEFBQcwAoZpZmlsZTovL1Zl
blFBLTJrOC1JQ0ExLnZlbnFhLnZlbmFmaS5jb20vQ2VydEVucm9sbC9WZW5RQS0y
azgtSUNBMS52ZW5xYS52ZW5hZmkuY29tX1ZlblFBIENsYXNzIEcgQ0EoMSkuY3J0
MDcGCCsGAQUFBzABhitodHRwOi8vdmVucWEtMms4LWljYTEudmVucWEudmVuYWZp
LmNvbS9vY3NwMAsGA1UdDwQEAwIFoDA7BgkrBgEEAYI3FQcELjAsBiQrBgEEAYI3
FQiBj4lyhISwavWdEIeW/3zEiRVggqTHRof7vysCAWQCARcwEwYDVR0lBAwwCgYI
KwYBBQUHAwEwGwYJKwYBBAGCNxUKBA4wDDAKBggrBgEFBQcDATAjBgNVHREEHDAa
ghhjZXJ0YWZpLWJvbmpvLnZlbmFmaS5jb20wDQYJKoZIhvcNAQEFBQADggEBAECq
dUFmousqf10dC6V8COtvwJlKw54e8RHbSCSmkkssd77X+vcZ76Nj9Jp9UJGd/ROQ
hQEkXWVklR38SU5Nh1Tb6Uj3yFgt4yLuOESLC7S+N7Qawwt4VgGlBrwx2eoRoU3r
5ptNL0yh3/EjN45727Ip8PW8TlTFESUVkMluZZJj+L8Hp3Ysp7dW4kZp4ACP7O3h
lD8dY3kNhPapH4zbgCUeX+eYONVF6v+hMBDdC26pfsTPxM0Q2wRnobazuRN4P2wj
buajuhfTXPNfJMm8WXuK54C5fkmh2AwVx/CosyAO1jvkgNz21l2dTLve/fXo5xrJ
qQvIVrfH+g+GOOdqFL8=
-----END CERTIFICATE-----`

var rootPEM = []string{`-----BEGIN CERTIFICATE-----
MIIGGzCCBQOgAwIBAgIKK0kjHQAAACaHWjANBgkqhkiG9w0BAQUFADBXMRMwEQYK
CZImiZPyLGQBGRYDY29tMRYwFAYKCZImiZPyLGQBGRYGdmVuYWZpMRUwEwYKCZIm
iZPyLGQBGRYFdmVucWExETAPBgNVBAMTCFZlblFBIENBMB4XDTE0MDMwOTA3MzIw
N1oXDTE2MDMwOTA3NDIwN1owXzETMBEGCgmSJomT8ixkARkWA2NvbTEWMBQGCgmS
JomT8ixkARkWBnZlbmFmaTEVMBMGCgmSJomT8ixkARkWBXZlbnFhMRkwFwYDVQQD
ExBWZW5RQSBDbGFzcyBHIENBMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKC
AQEArRMPTrwXRaD71Szy070JQC1lw+k9LfhD7tLqn7lr8Og242+lxFERFolQdYW6
v0uvcnZrJxGj+c3BJv7JLSdLumN4+N9z+COlHj2hIEmZuH//a3iKA5+Y+46wsWqM
MNFxonMUYDRtH/cocx/Ym7yE+8DyuTXc4zZ38hgFiusDrCH9d4zKEdQrPiLc5EgI
oewa0JFiudm7Kph2th75o+KwyUXEmfAUjIoGlCC7F/0GREPij7tOfgXKodNVXz3K
zfucg0p8vf3wd5K6xnzG1Fo/0o3GlHZmM5TfLDurx/mgmde8LftC6BHtdBC+pwp0
pvyMUJab0Br6AlZeZG04IrVPBwIDAQABo4IC3zCCAtswEgYJKwYBBAGCNxUBBAUC
AwEAATAjBgkrBgEEAYI3FQIEFgQUjR/UGsyByiYbUReb1Jzr9Tk5DmcwHQYDVR0O
BBYEFPN+IlbEeT7kUjtFyH6ilVyiWFp4MBkGCSsGAQQBgjcUAgQMHgoAUwB1AGIA
QwBBMAsGA1UdDwQEAwIBhjASBgNVHRMBAf8ECDAGAQH/AgEAMB8GA1UdIwQYMBaA
FEZWjbfYskbT3yHoRBI8UBNBLDsBMIIBWwYDVR0fBIIBUjCCAU4wggFKoIIBRqCC
AUKGP2h0dHA6Ly8yazgtdmVucWEtcGRjLnZlbnFhLnZlbmFmaS5jb20vQ2VydEVu
cm9sbC9WZW5RQSUyMENBLmNybIaBv2xkYXA6Ly8vQ049VmVuUUElMjBDQSxDTj0y
azgtdmVucWEtcGRjLENOPUNEUCxDTj1QdWJsaWMlMjBLZXklMjBTZXJ2aWNlcyxD
Tj1TZXJ2aWNlcyxDTj1Db25maWd1cmF0aW9uLERDPXZlbnFhLERDPXZlbmFmaSxE
Qz1jb20/Y2VydGlmaWNhdGVSZXZvY2F0aW9uTGlzdD9iYXNlP29iamVjdENsYXNz
PWNSTERpc3RyaWJ1dGlvblBvaW50hj1maWxlOi8vMms4LXZlbnFhLXBkYy52ZW5x
YS52ZW5hZmkuY29tL0NlcnRFbnJvbGwvVmVuUUEgQ0EuY3JsMIHEBggrBgEFBQcB
AQSBtzCBtDCBsQYIKwYBBQUHMAKGgaRsZGFwOi8vL0NOPVZlblFBJTIwQ0EsQ049
QUlBLENOPVB1YmxpYyUyMEtleSUyMFNlcnZpY2VzLENOPVNlcnZpY2VzLENOPUNv
bmZpZ3VyYXRpb24sREM9dmVucWEsREM9dmVuYWZpLERDPWNvbT9jQUNlcnRpZmlj
YXRlP2Jhc2U/b2JqZWN0Q2xhc3M9Y2VydGlmaWNhdGlvbkF1dGhvcml0eTANBgkq
hkiG9w0BAQUFAAOCAQEATNA8Cwul1UBQJHd+50b9g4jnXX7Kf+bUUmE9iJGOr2aB
E7/MAHGdjftvdJY0X+l1h8XS3Oaquo8trdGlxh9dBrQEYP2YlXnHgmY2xrI92bzd
ii3B9ZzLNKbMMPjowujZeB3GmytdNZvK+ghWZRZ9A2wNgYK4OTVJjlMDd9L8558T
yDnExeinI24X+z8CF1bYR5dX1NJThcwLwRPQd7EOQqYrfJV/7hsklbAypLAqePXt
P9B+DQ5bwFajgeL5en9UOfkJv34Y6xiZw5uZFuJD3QFqwpc5U6StaFfktYsKdYnK
2yktNHCiuRjFjzY27T2Ss2knEIbLjOJRZ+GRVxPm0Q==
-----END CERTIFICATE-----`,
	`-----BEGIN CERTIFICATE-----
MIIDnjCCAoagAwIBAgIQSTHIy/5JtJ5D2IopGzYu2zANBgkqhkiG9w0BAQUFADBX
MRMwEQYKCZImiZPyLGQBGRYDY29tMRYwFAYKCZImiZPyLGQBGRYGdmVuYWZpMRUw
EwYKCZImiZPyLGQBGRYFdmVucWExETAPBgNVBAMTCFZlblFBIENBMB4XDTEyMTEw
OTIyNDkwM1oXDTE3MTEwOTIyNTgzMlowVzETMBEGCgmSJomT8ixkARkWA2NvbTEW
MBQGCgmSJomT8ixkARkWBnZlbmFmaTEVMBMGCgmSJomT8ixkARkWBXZlbnFhMREw
DwYDVQQDEwhWZW5RQSBDQTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEB
AJbrRU0aJwpditlw4c8PlLEc4vhtMuTIVCE2eGmQ3ozSByo/rgfbnyXjTIXR9Oyf
fbL/1wMQ3wieZ6+oPmrd+65rD+yKZc+jZPSzuZCklLgTmn5PhKq3qG6A/g9Ak6v8
Ubhhf5ohcdv8gzWo22h0KX+PL0RBZS+Zo+HfC8dVuB3ulTBAcxoOJcVW2BM0A5B6
VfAz+Haf2W3iq3qOq68XaRJh1/ul7eceufH/WHITNWXOLneudrWElm4iU82DbKVR
xVCkckTOtP3MY6F7iG1NxYaDCmv412arZTwqaGOaVt6a0fvF9S/fs4U+S5A8qRkN
8AF8vKF3tWArFnOfiZ+rHhsCAwEAAaNmMGQwEwYJKwYBBAGCNxQCBAYeBABDAEEw
CwYDVR0PBAQDAgGGMA8GA1UdEwEB/wQFMAMBAf8wHQYDVR0OBBYEFEZWjbfYskbT
3yHoRBI8UBNBLDsBMBAGCSsGAQQBgjcVAQQDAgEAMA0GCSqGSIb3DQEBBQUAA4IB
AQAVuy2zduBG6XXUTx5gnZQlAa+fuPv/7G332XOUqct6D5RdUN9Ud9Q3c1GcUrdx
t71om/qWw1JhgnvHY2Ilopq1EtwYcrpf+Vq8FGK0eZKkT70AKEgSM6+86as7sqQs
3nIoJFBYOBLm1Dz4zms51Vgi75qCl4sW0TksIPqF6ZFRsHTyfaNp+6tDncivhfJ0
/72oturg7T2X2Voj2F74mO3+ulzdXH06xbd1NFRozaYgEB21U5S0shSrdOGHB1R8
tgKbuMWPjeVvjGy45NK5XTIDQLzr9fbLM3+7ODfbj0qtvvvpqrUwlhKn3052RgNL
2pDjcSrk0YMU5/VX4IWr7vrZ
-----END CERTIFICATE-----`}

func TestNewPEMCollection(t *testing.T) {
	_, err := NewPEMCollection(nil, nil, nil)
	if err != nil {
		t.Fatalf("NewCollection should be created with a nil certificate")
	}

	cert, pk, err := generateTestCertificate()
	if err != nil {
		t.Fatalf("Error generating test certificate\nError: %s", err)
	}

	col, err := NewPEMCollection(cert, pk, []byte("test"))
	if err != nil {
		t.Fatalf("Error creating collection. Error: %s", err)
	}
	if col.Certificate == "" {
		t.Fatalf("PEMCertificate in collection is empty")
	}
	if col.PrivateKey == "" {
		t.Fatalf("PEMPrivateKey in collection is empty")
	}
}

func TestAddChainElementToPEMCollection(t *testing.T) {
	p, _ := pem.Decode([]byte(pkPEM))
	b, err := x509.DecryptPEMBlock(p, []byte("Passw0rd"))
	if err != nil {
		t.Fatalf("Error: %s", err)
	}
	pk, err := x509.ParsePKCS1PrivateKey(b)
	if err != nil {
		t.Fatalf("Error: %s", err)
	}

	p, _ = pem.Decode([]byte(certPEM))
	cert, err := x509.ParseCertificate(p.Bytes)
	if err != nil {
		t.Fatalf("Error: %s", err)
	}

	col, err := NewPEMCollection(cert, pk, nil)
	if err != nil {
		t.Fatalf("Error: %s", err)
	}

	for _, s := range rootPEM {
		p, _ = pem.Decode([]byte(s))
		root, err := x509.ParseCertificate(p.Bytes)
		if err != nil {
			t.Fatalf("Error: %s", err)
		}

		err = col.AddChainElement(root)
		if err != nil {
			t.Fatalf("Error: %s", err)
		}
	}

	if len(col.Chain) != 2 {
		t.Fatalf("PEM Chain did not contain the expected number of elements 2, actual count %d", len(col.Chain))
	}
}

func TestPEMCollectionFromBytes(t *testing.T) {
	var bytes []byte = []byte{}

	t.Log("empty")
	pcc, err := PEMCollectionFromBytes(bytes, ChainOptionRootLast)
	if err != nil {
		t.Fatalf("Error: %s", err)
	}

	t.Log("default order (cert first)")
	bytes = append(bytes, []byte(certPEM)...)
	bytes = append(bytes, '\n')
	bytes = append(bytes, []byte(rootPEM[0])...)
	bytes = append(bytes, '\n')
	bytes = append(bytes, []byte(rootPEM[1])...)
	bytes = append(bytes, '\n')
	bytes = append(bytes, []byte(pkPEM)...)

	pcc, err = PEMCollectionFromBytes(bytes, ChainOptionRootLast)
	if err != nil {
		t.Fatalf("Error: %s", err)
	}
	p, _ := pem.Decode([]byte(pcc.Certificate))
	cert, err := x509.ParseCertificate(p.Bytes)
	if err != nil || cert.Subject.CommonName != "certafi-bonjo.venafi.com" {
		t.Fatalf("failed read certificate from bytes: %s\nbytes:%s", err, string(bytes))
	}
	if pcc.PrivateKey == "" {
		t.Fatalf("failed to read private key from bytes: %s", string(bytes))
	}
	if len(pcc.Chain) != 2 {
		t.Fatalf("failed to read chain from bytes: %s", string(bytes))
	}

	t.Log("reverse order (chain first)")
	bytes = []byte{}
	bytes = append(bytes, []byte(rootPEM[1])...)
	bytes = append(bytes, '\n')
	bytes = append(bytes, []byte(rootPEM[0])...)
	bytes = append(bytes, '\n')
	bytes = append(bytes, []byte(certPEM)...)
	bytes = append(bytes, '\n')
	bytes = append(bytes, []byte(pkPEM)...)

	pcc, err = PEMCollectionFromBytes(bytes, ChainOptionRootFirst)
	if err != nil {
		t.Fatalf("Error: %s", err)
	}
	p, _ = pem.Decode([]byte(pcc.Certificate))
	cert, err = x509.ParseCertificate(p.Bytes)
	if err != nil || cert.Subject.CommonName != "certafi-bonjo.venafi.com" {
		t.Fatalf("failed read certificate from bytes: %s\nbytes:%s", err, string(bytes))
	}
	if pcc.PrivateKey == "" {
		t.Fatalf("failed to read private key from bytes: %s", string(bytes))
	}
	if len(pcc.Chain) != 2 {
		t.Fatalf("failed to read chain from bytes: %s", string(bytes))
	}

	t.Log("no chain")
	bytes = []byte{}
	bytes = append(bytes, []byte(certPEM)...)
	bytes = append(bytes, '\n')
	bytes = append(bytes, []byte(pkPEM)...)

	pcc, err = PEMCollectionFromBytes(bytes, ChainOptionRootLast)
	if err != nil {
		t.Fatalf("Error: %s", err)
	}
	p, _ = pem.Decode([]byte(pcc.Certificate))
	cert, err = x509.ParseCertificate(p.Bytes)
	if err != nil || cert.Subject.CommonName != "certafi-bonjo.venafi.com" {
		t.Fatalf("failed read certificate from bytes: %s\nbytes:%s", err, string(bytes))
	}
	if pcc.PrivateKey == "" {
		t.Fatalf("failed to read private key from bytes: %s", string(bytes))
	}
	if len(pcc.Chain) != 0 {
		t.Fatalf("should be no chaing in bytes: %s", string(bytes))
	}

	t.Log("cert only")
	bytes = []byte{}
	bytes = append(bytes, []byte(certPEM)...)

	pcc, err = PEMCollectionFromBytes(bytes, ChainOptionRootLast)
	if err != nil {
		t.Fatalf("Error: %s", err)
	}
	p, _ = pem.Decode([]byte(pcc.Certificate))
	cert, err = x509.ParseCertificate(p.Bytes)
	if err != nil || cert.Subject.CommonName != "certafi-bonjo.venafi.com" {
		t.Fatalf("failed read certificate from bytes: %s\nbytes:%s", err, string(bytes))
	}
	pcc, err = PEMCollectionFromBytes(bytes, ChainOptionRootFirst)
	if err != nil {
		t.Fatalf("Error: %s", err)
	}
	p, _ = pem.Decode([]byte(pcc.Certificate))
	cert, err = x509.ParseCertificate(p.Bytes)
	if err != nil || cert.Subject.CommonName != "certafi-bonjo.venafi.com" {
		t.Fatalf("failed read certificate from bytes: %s\nbytes:%s", err, string(bytes))
	}
	if pcc.PrivateKey != "" {
		t.Fatalf("should be no private key in bytes: %s", string(bytes))
	}
	if len(pcc.Chain) != 0 {
		t.Fatalf("should be no chaing in bytes: %s", string(bytes))
	}
}

func TestAddPrivateKey(t *testing.T) {
	pk, _ := GenerateRSAPrivateKey(512)

	pcc, _ := NewPEMCollection(nil, nil, nil)
	err := pcc.AddPrivateKey(pk, []byte("newPassw0rd!"))
	if !strings.Contains(pcc.PrivateKey, "BEGIN RSA PRIVATE KEY") || err != nil {
		t.Fatalf("collection should have PEM encoded private key")
	}
	if !strings.Contains(pcc.PrivateKey, "ENCRYPTED") {
		t.Fatalf("collection should have private key being encrypted")
	}

	pcc, err = NewPEMCollection(nil, nil, nil)
	pcc.AddPrivateKey(pk, nil)
	if strings.Contains(pcc.PrivateKey, "ENCRYPTED") || err != nil {
		t.Fatalf("collection should have private key being un-encrypted")
	}

	pcc, err = NewPEMCollection(nil, nil, nil)
	pcc.AddPrivateKey(pk, []byte(""))
	if strings.Contains(pcc.PrivateKey, "ENCRYPTED") || err != nil {
		t.Fatalf("collection should have private key being un-encrypted")
	}
}

func TestChainOptionFromString(t *testing.T) {
	co := ChainOptionFromString("RoOt-fIrSt")
	if co != ChainOptionRootFirst {
		t.Fatalf("ChainOptionFromString did not return the expected value of %v -- Actual value %v", ChainOptionRootFirst, co)
	}
	co = ChainOptionFromString("IGNORE")
	if co != ChainOptionIgnore {
		t.Fatalf("ChainOptionFromString did not return the expected value of %v -- Actual value %v", ChainOptionIgnore, co)
	}
	co = ChainOptionFromString("RoOt-LaSt")
	if co != ChainOptionRootLast {
		t.Fatalf("ChainOptionFromString did not return the expected value of %v -- Actual value %v", ChainOptionRootLast, co)
	}
	co = ChainOptionFromString("some value")
	if co != ChainOptionRootLast {
		t.Fatalf("ChainOptionFromString did not return the expected value of %v -- Actual value %v", ChainOptionRootLast, co)
	}
}
