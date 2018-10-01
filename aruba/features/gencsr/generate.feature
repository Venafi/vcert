Feature: Generating certificate request using options

  As a user I want to generate certificate requests with various properties

  Background:
    And the default aruba exit timeout is 180 seconds

  Scenario: when all the options are used
  When I try to run `vcert gencsr -csr-file csr.pem -key-file k.pem -cn vfidev.example.com -san-dns www.vfidev.example.com -san-dns ww1.vfidev.example.com -no-prompt -san-email aa@ya.ru -san-email bb@ya.ru -san-ip 1.1.1.1 -san-ip 2.2.2.2 -l L -st ST -c C -ou OU -o O -key-type ecdsa -key-curve p384`
    Then the exit status should be 0
    Then it should write CSR to the file named "csr.pem"
    Then I decode CSR from file "csr.pem"
      And that CSR Subject should contain "C = C"
      And that CSR Subject should contain "ST = ST"
      And that CSR Subject should contain "L = L"
      And that CSR Subject should contain "O = O"
      And that CSR Subject should contain "OU = OU"
      And that CSR Subject should contain "CN = vfidev.example.com"

      And that CSR should contain "DNS:www.vfidev.example.com"
      And that CSR should contain "DNS:ww1.vfidev.example.com"
      And that CSR should contain "email:aa@ya.ru"
      And that CSR should contain "email:bb@ya.ru"
      And that CSR should contain "IP Address:1.1.1.1"
      And that CSR should contain "IP Address:2.2.2.2"
      And that CSR should contain "CURVE: P-384"

  Scenario: explicitly verifying CSR and private key modulus
    When I run `vcert gencsr -csr-file csr.pem -key-file k.pem -no-prompt -cn vfidev.example.com`
    And I run `openssl req -modulus -noout -in csr.pem`
    And I remember the output
    And I run `openssl rsa -modulus -noout -in k.pem`
    Then the outputs should be the same

  Scenario: generating CSR with 1024 bit RSA private key type
    When I run `vcert gencsr -csr-file csr.pem -key-file k.pem -no-prompt -cn vfidev.example.com -key-size 1024`
    Then it should write CSR to the file named "csr.pem"
    Then I decode CSR from file "csr.pem"
    And that CSR should contain "Public-Key: (1024 bit)"

  Scenario: verifying CSR and private key modulus
    When I run `vcert gencsr -csr-file csr.pem -key-file k.pem -no-prompt -cn vfidev.example.com`
    Then CSR in "csr.pem" file and private key in "k.pem" file should have the same modulus

  Scenario: where two CSR generated independently have different key modulus
    When I successfully run `vcert gencsr -csr-file csr1.pem -key-file k1.pem -no-prompt -cn vfidev.example.com`
    When I successfully run `vcert gencsr -csr-file csr2.pem -key-file k2.pem -no-prompt -cn vfidev.example.com`
    Then CSR in "csr1.pem" file and private key in "k2.pem" file should not have the same modulus


#
# $ openssl req -text -noout -in csr.pem
# Certificate Request:
#     Data:
#         Version: 1 (0x0)
#         Subject: C = C, ST = ST, L = L, O = O, OU = OU, CN = vfidev.example.com
#         Subject Public Key Info:
#             Public Key Algorithm: id-ecPublicKey
#                 Public-Key: (384 bit)
#                 pub:
#                     04:42:4b:c6:97:94:b3:fe:3d:5a:94:e7:8b:10:6d:
#                     55:5a:d8:e0:52:27:3d:38:d1:41:21:46:a0:a9:fd:
#                     8e:b6:9a:b7:b5:2e:57:3b:f9:59:4e:7f:1c:f4:5d:
#                     4c:80:3e:d6:98:12:d6:23:3e:5b:74:12:d8:cf:51:
#                     2e:78:21:eb:c8:6e:5b:0c:be:e8:75:a9:8f:0e:29:
#                     0b:fe:44:8b:b7:b8:19:f2:75:38:72:a0:8a:b1:01:
#                     b9:e6:20:08:0d:7e:d1
#                 ASN1 OID: secp384r1
#                 NIST CURVE: P-384
#         Attributes:
#         Requested Extensions:
#             X509v3 Subject Alternative Name:
#                 DNS:www.vfidev.example.com, DNS:ww1.vfidev.example.com, email:aa@ya.ru, email:bb@ya.ru, IP Address:1.1.1.1, IP Address:2.2.2.2
#     Signature Algorithm: ecdsa-with-SHA384
#          30:66:02:31:00:c9:fb:b1:90:22:19:63:07:c4:20:20:ec:40:
#          b3:14:d7:82:ec:5e:44:93:6a:ca:e0:4f:2b:ee:69:ad:67:4d:
#          ea:cf:9c:82:79:7c:7d:20:98:fe:61:56:0d:23:67:a9:3d:02:
#          31:00:83:e9:00:22:49:d5:8d:a1:1e:02:3e:cc:71:1d:fa:7f:
#          61:99:88:f6:de:62:8e:03:b0:7b:3e:10:c6:aa:05:ef:a4:55:
#          df:e2:7d:f2:15:48:03:1c:8a:06:19:13:87:67
#
