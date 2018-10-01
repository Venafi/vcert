Feature: renew action returns error if incorrect options are used

  Background:
    And the default aruba exit timeout is 180 seconds

  Scenario: where renew actions does not allow options: -cn, -c, -o, -ou, -l, -st
    Given I enroll random certificate in TPP with -no-prompt -pickup-id-file p.txt
      And it should retrieve certificate
      And it should write Pickup ID to the file "p.txt"
    When I renew the certificate in TPP with -no-prompt -no-pickup -id file:p.txt -cn xxx.venafi.example.com
    Then it should fail with "Renewal does not allow options: -cn, -c, -o, -ou, -l, -st"
    When I renew the certificate in TPP with -no-prompt -no-pickup -id file:p.txt -c  ccc
    Then it should fail with "Renewal does not allow options: -cn, -c, -o, -ou, -l, -st"
    When I renew the certificate in TPP with -no-prompt -no-pickup -id file:p.txt -o  ooo
    Then it should fail with "Renewal does not allow options: -cn, -c, -o, -ou, -l, -st"
    When I renew the certificate in TPP with -no-prompt -no-pickup -id file:p.txt -ou uuu
    Then it should fail with "Renewal does not allow options: -cn, -c, -o, -ou, -l, -st"
    When I renew the certificate in TPP with -no-prompt -no-pickup -id file:p.txt -l  lll
    Then it should fail with "Renewal does not allow options: -cn, -c, -o, -ou, -l, -st"
    When I renew the certificate in TPP with -no-prompt -no-pickup -id file:p.txt -st ttt
    Then it should fail with "Renewal does not allow options: -cn, -c, -o, -ou, -l, -st"


  Scenario: where it returns error if both -id and -thumbprint are used
    Given I enroll random certificate in TPP with -no-prompt -pickup-id-file p.txt -cert-file c.pem
      And it should retrieve certificate
      And it should write Pickup ID to the file "p.txt"
      And it should write certificate to the file named "c.pem"
    When I renew the certificate in TPP with -no-prompt -no-pickup -id file:p.txt -thumbprint file:c.pem
    Then it should fail with "-id and -thumbprint cannot be used both at the same time"




