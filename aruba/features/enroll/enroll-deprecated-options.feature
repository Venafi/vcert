Feature: Tests with deprecated TPP options

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
    When I enroll a certificate in TPPdeprecated with -csr service -key-type rsa -key-size 4096 -cn service-gen-rsa.vcert.example -format json -key-password newPassw0rd!
    Then it should retrieve certificate
    Then I get JSON response
    And that certificate should contain "Public-Key: (4096 bit)"

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
    When I enroll certificate using TPPdeprecated with -csr service -cn service-gen-pickup-id-as-param.vcert.example -no-pickup
    Then it should post certificate request
    And I retrieve the certificate from TPPdeprecated using the same Pickup ID with -key-password newPassw0rd! -timeout 59
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
    When I enroll certificate using TPPdeprecated with -csr service -cn service-gen-pickup-id-in-file.vcert.example -no-pickup -pickup-id-file pickup_id.txt
    Then it should post certificate request
    And I retrieve the certificate from TPPdeprecated with -pickup-id-file pickup_id.txt -key-password newPassw0rd! -timeout 59
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
    When I enroll certificate using TPPdeprecated with -csr file:user-provided-rsa.req -cert-file c.pem
    And it should retrieve certificate
    And I decode certificate from file "c.pem"
    Then that certificate should contain "Public-Key: (4096 bit)"

