@VAAS
Feature: provision to cloud keystore

  As a user
  I want provision certificates to cloud keystore from Venafi Control Plane

  Background:
    And the default aruba exit timeout is 180 seconds

  Scenario Outline: Enroll certificate and execute provisioning for cloud keystore
    Given I enroll a random certificate with defined platform VCP with -csr service -no-prompt
    And I remember the output
    And I use previous Pickup ID to provision from VCP a certificate to cloudkeystore "<cloudkeystore>" setting keystore and provider names
    And I remember the output
    And it should output cloud ID
    Then I clean up previous installed certificate from cloudkeystore
    Examples:
      | cloudkeystore    |
      | GOOGLE           |

  Scenario Outline: Enroll certificate and execute provisioning for cloud keystore and get output in JSON
    Given I enroll a random certificate with defined platform VCP with -csr service -no-prompt
    And I remember the output
    And I use previous Pickup ID to provision from VCP a certificate to cloudkeystore "<cloudkeystore>" setting keystore and provider names with -format json
    And I remember the output
      And it should output cloud ID in JSON
    Then I clean up previous installed certificate from cloudkeystore
    Examples:
      | cloudkeystore    |
      | GOOGLE           |
