@TPP
Feature: few more tests from Ryan

  As a user
  I want to be sure they all pass

  Background:
    And the default aruba exit timeout is 180 seconds

# cls
# title ~ Service Generated CSR with RSA key ~
# VCert enroll -tpp-url %TPP_URL% -tpp-user %TPP_USER% -tpp-password %TPP_PASS% -z "%POLICY%" -csr service -key-type rsa -key-size 4096 -cn service-gen-rsa.vcert.example -format json -key-password %KEY_PASS%
# if ERRORLEVEL 1 goto :DONE
# timeout /t 10
  Scenario: ~ Service Generated CSR with RSA key ~
    When I enroll a certificate with dummy password in TPP with -csr service -key-type rsa -key-size 4096 -cn service-gen-rsa.vcert.example -format json
    Then it should retrieve certificate
    Then I get JSON response
    And that certificate should contain "Public-Key: (4096 bit)"

# cls
# title ~ Service Generated CSR with ECC key ~
# VCert enroll -tpp-url %TPP_URL% -tpp-user %TPP_USER% -tpp-password %TPP_PASS% -z "%ECC_POLICY%" -csr service -key-type ecdsa -key-curve p521 -cn service-gen-ecc.vcert.example -format json -key-password %KEY_PASS%
# if ERRORLEVEL 1 goto :DONE
# timeout /t 10
  Scenario: ~ Service Generated CSR with ECC key ~
    When I enroll random certificate with dummy password using TPPecdsa with -csr service -key-type ecdsa -key-curve p521 -format json
    Then it should post certificate request
    And it should retrieve certificate
    And the JSON response at "PrivateKey" should include "-----BEGIN EC PRIVATE KEY-----"
    And the JSON response at "PrivateKey" should include "ENCRYPTED"

# cls
# title ~ Service Generated CSR pickup later ID as param ~
# for /f "tokens=2 delims==" %%i in ( 'VCert enroll -tpp-url %TPP_URL% -tpp-user %TPP_USER% -tpp-password %TPP_PASS% -z "%POLICY%" -csr service -cn service-gen-pickup-id-as-param.vcert.example -no-pickup 2^>^&1 ^| find "PickupID="' ) do set PICKUP_ID=%%i
# echo PickupID=%PICKUP_ID%
# timeout /t 15 /nobreak
# echo.
# VCert pickup -tpp-url %TPP_URL% -tpp-user %TPP_USER% -tpp-password %TPP_PASS% -pickup-id %PICKUP_ID% -key-password %KEY_PASS%
# if ERRORLEVEL 1 goto :DONE
# timeout /t 10
  Scenario: ~ Service Generated CSR pickup later ID as param ~
    When I enroll certificate using TPP with -csr service -cn service-gen-pickup-id-as-param.vcert.example -no-pickup
    Then it should post certificate request
    And I retrieve the certificate from TPP using the same Pickup ID and using a dummy password with -timeout 59
    Then it should retrieve certificate
    Then it should output encrypted private key

# cls
# title ~ Service Generated CSR pickup later ID in file~
# VCert enroll -tpp-url %TPP_URL% -tpp-user %TPP_USER% -tpp-password %TPP_PASS% -z "%POLICY%" -csr service -cn service-gen-pickup-id-in-file.vcert.example -no-pickup -pickup-id-file pickup_id.txt
# timeout /t 15 /nobreak
# echo.
# VCert pickup -tpp-url %TPP_URL% -tpp-user %TPP_USER% -tpp-password %TPP_PASS% -pickup-id-file pickup_id.txt -key-password %KEY_PASS%
# if ERRORLEVEL 1 goto :DONE
# timeout /t 10
  Scenario: ~ Service Generated CSR pickup later ID in file~
    When I enroll certificate using TPP with -csr service -cn service-gen-pickup-id-in-file.vcert.example -no-pickup -pickup-id-file pickup_id.txt
    Then it should post certificate request
    And I retrieve the certificate using a dummy password from TPP with -pickup-id-file pickup_id.txt -timeout 59
    Then it should retrieve certificate
    Then it should output encrypted private key


# cls
# title ~ User Provided CSR with RSA key ~
# VCert gencsr -cn user-provided-rsa.vcert.example -key-type rsa -key-size 4096 -key-file user-provided-rsa.key -csr-file user-provided-rsa.req -no-prompt
# echo.
# VCert enroll -tpp-url %TPP_URL% -tpp-user %TPP_USER% -tpp-password %TPP_PASS% -z "%POLICY%" -csr file:user-provided-rsa.req
# if ERRORLEVEL 1 goto :DONE
# timeout /t 10
  Scenario: ~ User Provided CSR with RSA key ~
    Given I generate CSR with -cn user-provided-rsa.vcert.example -key-type rsa -key-size 4096 -key-file user-provided-rsa.key -csr-file user-provided-rsa.req -no-prompt
    When I enroll certificate using TPP with -csr file:user-provided-rsa.req -cert-file c.pem
    And it should retrieve certificate
    And I decode certificate from file "c.pem"
    Then that certificate should contain "Public-Key: (4096 bit)"

# cls
# title ~ User Provided CSR with ECC key ~
# VCert gencsr -cn user-provided-ecc.vcert.example -key-type ecdsa -key-curve p521 -key-file user-provided-ecc.key -csr-file user-provided-ecc.req -no-prompt
# echo.
# VCert enroll -tpp-url %TPP_URL% -tpp-user %TPP_USER% -tpp-password %TPP_PASS% -z "%ECC_POLICY%" -csr file:user-provided-ecc.req
# if ERRORLEVEL 1 goto :DONE
# timeout /t 10
  Scenario: ~ User Provided CSR with ECC key ~
    Given I generate CSR with -cn user-provided-ecc.vcert.example -key-type ecdsa -key-curve p521 -key-file user-provided-ecc.key -csr-file user-provided-ecc.req -no-prompt
    When I enroll certificate using TPPecdsa with -csr file:user-provided-ecc.req -cert-file c.pem
    And it should retrieve certificate
    And I decode certificate from file "c.pem"
    Then that certificate should contain "CURVE: P-521"

#  cls
#  title ~ Service Generated CSR with SANS and should be no log output ~
#  VCert enroll -tpp-url %TPP_URL% -tpp-user %TPP_USER% -tpp-password %TPP_PASS% -z "%POLICY%" -csr service -cn service-gen-with-sans.vcert.example -san-dns one.vcert.example -san-dns two.vcert.example -san-ip 10.20.30.40 -san-ip 198.168.144.120 -san-email zack.jackson@vcert.example -format json -key-password %KEY_PASS% 2>nul
#  if ERRORLEVEL 1 goto :DONE
#  timeout /t 10
  Scenario: ~ Service Generated CSR with SANS and should be no log output ~
    When I enroll random certificate with dummy password using TPP with -csr service -san-dns one.vcert.example -san-dns two.vcert.example -san-ip 10.20.30.40 -san-ip 198.168.144.120 -san-email zack.jackson@vcert.example -format json
    And I get JSON response
    And that certificate should contain "DNS:one.vcert.example"
    And that certificate should contain "DNS:two.vcert.example"
    And that certificate should contain "email:zack.jackson@vcert.example"
    And that certificate should contain "IP Address:10.20.30.40"
    And that certificate should contain "IP Address:198.168.144.120"

# cls
# title ~ User Provided CSR with SANs ~
# VCert gencsr -cn user-provided-with-sans.vcert.example -san-dns one.vcert.example -san-dns two.vcert.example -san-ip 10.20.30.40 -san-ip 198.168.144.120 -san-email zack.jackson@vcert.example -key-file user-provided-with-sans.key -csr-file user-provided-with-sans.req -key-password %KEY_PASS%
# echo.
# VCert enroll -tpp-url %TPP_URL% -tpp-user %TPP_USER% -tpp-password %TPP_PASS% -z "%POLICY%" -csr file:user-provided-with-sans.req
# if ERRORLEVEL 1 goto :DONE
# timeout /t 10
  Scenario: ~ User Provided CSR with SANs ~
    Given I generate CSR using dummy password with flags -cn user-provided-with-sans.vcert.example -san-dns one.vcert.example -san-dns two.vcert.example -san-ip 10.20.30.40 -san-ip 198.168.144.120 -san-email zack.jackson@vcert.example -key-file user-provided-with-sans.key -csr-file user-provided-with-sans.req
    And I enroll certificate using TPP with -csr file:user-provided-with-sans.req -cert-file c.pem
    And I decode certificate from file "c.pem"
    And that certificate should contain "DNS:one.vcert.example"
    And that certificate should contain "DNS:two.vcert.example"
    And that certificate should contain "email:zack.jackson@vcert.example"
    And that certificate should contain "IP Address:10.20.30.40"
    And that certificate should contain "IP Address:198.168.144.120"
    And that certificate Subject should contain "CN = user-provided-with-sans.vcert.example"

# cls
# title ~ User Provided CSR with full Subject DN ~
# VCert gencsr -cn user-provided-full-subject.vcert.example -ou "DevOps Integrations" -o "Swordfish Security" -l "St. Petersburg" -st Russia -c RU -key-file user-provided-full-subject.key -csr-file user-provided-full-subject.req -key-password %KEY_PASS%
# echo.
# VCert enroll -tpp-url %TPP_URL% -tpp-user %TPP_USER% -tpp-password %TPP_PASS% -z "%POLICY%" -csr file:user-provided-full-subject.req
# if ERRORLEVEL 1 goto :DONE
# timeout /t 10
#   Scenario: ~ User Provided CSR with full Subject DN ~
#     Given I generate CSR using dummy password with flags -cn user-provided-full-subject.vcert.example -ou "DevOps Integrations" -o "Swordfish Security" -l "St. Petersburg" -st Russia -c RU -key-file user-provided-full-subject.key -csr-file user-provided-full-subject.req
#     And I enroll certificate using TPP with -csr file:user-provided-full-subject.req -format json
#     And I get JSON response
#     Then that certificate Subject should contain "C = RU"
#     And that certificate Subject should contain "ST = Russia"
#     And that certificate Subject should contain "L = St. Petersburg"
#     And that certificate Subject should contain "O = Swordfish Security"
#     And that certificate Subject should contain "OU = DevOps Integrations"
#     And that certificate Subject should contain "CN = user-provided-full-subject.vcert.example"
