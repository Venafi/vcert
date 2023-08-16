Feature: Enroll certificate using Firefly

  As a user
  I want to enroll certificates with Firefly platform

  Background:
    Given the default aruba exit timeout is 180 seconds

  Scenario: Simple enroll with Firefly
    When I enroll a random certificate with defined platform Firefly with -key-type ecdsa -key-curve p256 -csr service -no-prompt
    Then it should request certificate

  Scenario: Enroll using CSR with Firefly
    Given I generate random CSR with -no-prompt -csr-file csr.pem -key-file k.pem
      And it should write CSR to the file named "csr.pem"
      And it should write private key to the file named "k.pem"
    And I enroll a random certificate with defined platform Firefly with -csr file:csr.pem
      Then it should request certificate