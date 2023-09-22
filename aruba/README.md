
# Cucumber tests setup

## Cucumber tests environment variables

We need to define the following environment variables, you can find out more
about you need for them in [here](./../README.md#sdk-environment-variables):

- TPP_URL
- TPP_USER
- TPP_PASSWORD
- TPP_ACCESS_TOKEN
- TPP_ZONE
- TPP_ZONE_ECDSA
- CLOUD_URL
- CLOUD_APIKEY
- CLOUD_ZONE

Then also we need to define these, that are as well needed for cucumber tests: 

**TPP_IP**

The IP of your TPP instance, we will need it to add it in the Docker container `/etc/hosts` file

**TPP_CN**

The Common Name of your TPP instance, we will to add it in the Docker container `/etc/hosts` file

**TPP_TRUST_BUNDLE**

When running the Docker container, you need to let know cucumber where to find the TPP trust bundle, this is
so we can make secure connection. In this case this should be the same as depicted in the [Dockerfile](./Dockerfile):
`/vcert/tpp/`
plus the name of the file (we recommend this name, also is git-ignored by our project, you can see it [here](./../.gitignore))
`tpp-bundle.pem`
resulting in full path:
`/vcert/tpp/tpp-bundle.pem`

>**Note:** While testing/debugging directly on IDE, you will to set this value as where it's located in your local machine.

**FIREFLY_CA_BUNDLE**

When running the Docker container, you need to let know cucumber where to find the TPP trust bundle, this is
so we can make secure connection. In this case this should be the same as depicted in the [Dockerfile](./Dockerfile):
`/vcert/firefly/`
plus the name of the file (we recommend this name, also is git-ignored by our project, you can see it [here](./../.gitignore))
`firefly-bundle.pem`
resulting in full path:
`/vcert/aruba/firefly-bundle.pem`

**FIREFLY_ZONE**

We use OKTA as our Identity Provider for Firefly, so you will need the following env variables:

**OKTA_AUTH_SERVER**

You auth OKTA server, you should be able to find how is formed in your OKTA Developer Panel

E.g.:
`https://dev-fdsfdsfsdf.okta.com/oauth2/sfdsfsdfsdfd"`

We support 2 flows for e2e testing. "Secret Auth" and "Password Auth":

For "Secret Auth" flow you need to defined following variables:

**OKTA_CLIENT_ID**: Your "Secret Auth" flow application ID

**OKTA_CLIENT_SECRET**: Your "Secret Auth" flow secret string

For "Password Auth" flow you need to defined following variables:

**OKTA_CLIENT_ID_PASS**: Your "Password Auth" flow application ID

**OKTA_CREDS_USR**: Your username for "Password Auth" flow

**OKTA_CREDS_PSW**: Your password for "Password Auth" flow

## Playbook testing with cucumber and aruba

In order to write e2e testing with aruba for playbook, there are 3 steps:

- Writing the Playbook YAML
- Executing and validating the output
- Removing generated files

### Writing the Playbook YAML

you'll need to provide the structure of the YAML as
if you are describing every value for it as the following Ruby classes:

- Installation
- Location
- Object
- Request
- PlaybookTask

All of them mimic the YAML file field counterparts (you can see all the available value for them in [here](./features/playbook/support/aruba.rb))

The starting point for creating a Playbook YAML file will be as follows:

1. `Given I have playbook with <Venafi Platform> connection details`

For example, for TPP this will create the equivalent of:
```YAML
config:
  connection:
    type: tpp
    credentials:
      clientId: vcert-sdk
      accessToken: '{{ Env "TPP_ACCESS_TOKEN" }}'
      refreshToken: '{{ Env "TPP_REFRESH_TOKEN" }}'
    trustBundle: /path/to/my/trustbundle.pem # TrustBundle for TPP connection
    url: https://tpp.venafi.example # URL to TPP instance
```

2. `I have playbook with certificateTasks block`

This will initialize a certificate block, it's important doing these initializations before actually populating
keys and values for the object.

3. `And I have playbook with task named "myCertificateInstallation"`

This will start populating the task with name as "myCertificateInstallation"

4. `And task named "myCertificateInstallation" has request`

Now we are starting to populate the request block

5. Populating following request values:
`And task named "myCertificateInstallation" has request with "csr" value "service"`
`And task named "myCertificateInstallation" has request with "keyType" value "rsa"`
`And task named "myCertificateInstallation" has request with "keySize" value "4096"`


6. `And task named "myCertificateInstallation" has request with default <Venafi Platform> zone`

This will look for the zone that you had set for environment variables depending on the Venafi Platform you are writing
this test:

- **TPP_ZONE** (TLSPDC)
- **CLOUD_ZONE** (TLSPC)
- **FIREFLY_ZONE**

From 2 to 6 we have produced the following block:

```YAML
certificateTasks:
      name: myCertificateInstallation
	  request:
	    csr: service
	    keyType: rsa
	    keySize: 4096
	    zone: Devops\vcert
```
7. `And task named "myCertificateInstallation" request has subject`

In here we start providing a subject block

8. Then we start populating subject values:

```
And task named "myCertificateInstallation" request has subject with "country" value "US"
And task named "myCertificateInstallation" request has subject with "locality" value "Salt Lake City"
And task named "myCertificateInstallation" request has subject with "province" value "Utah"
And task named "myCertificateInstallation" request has subject with "organization" value "Venafi Inc"
And task named "myCertificateInstallation" request has subject with "orgUnits" value "engineering,marketing"
```

you could also do the following step to do the above:

`And task named "myCertificateInstallation" request has subject with default values`

9. `And task named "myCertificateInstallation" request has subject random CommonName`

We use this predefined step to create a random name for us.

10. `And task named "myCertificateInstallation" has installations`

We provide an installation block

11. `And task named "myCertificateInstallation" has installation format PEM with file name "c1.cer", chain name "ch1.cer", key name "k1.pem" with installation`

From step 7 to 11, we have generated this block:

```YAML
    subject:
      country: US
      locality: Salt Lake City
      province: Utah
      organization: Venafi Inc
	  orgUnits:
	    - engineering
	    - marketing
      commonName: 1692387475-0dgrf.venafi.example.com
  installations:
  - format: PEM
    file: '{{- Env "PWD" }}/tmp/aruba/cert.cer'
    chainFile: '{{- Env "PWD" }}/tmp/aruba/chain.cer'
    keyFile: '{{- Env "PWD" }}/tmp/aruba/key.pem'
    afterInstallAction: echo SuccessInstall
```

12. `And I created playbook named "<config-file>" with previous content`

This is the last step for generating the YAML, we need this to convert the Ruby generated objects
to an actual Playbook that VCert will run.

Then putting all together, we have the resulting YAML:

```YAML
---
config:
	connection:
		type: tpp
		credentials:
			clientId: vcert-sdk
			accessToken: '{{ Env "TPP_ACCESS_TOKEN" }}'
		trustBundle: /path/to/my/trustbundle.pem # TrustBundle for TPP connection
		url: https://tpp.venafi.example # URL to TPP instance
certificateTasks:
	name: myCertificateInstallation
	request:
		csr: service
		keyType: rsa
		keySize: 4096
		zone: Devops\vcert
    	subject:
			country: US
			locality: Salt Lake City
			province: Utah
			organization: Venafi Inc
			orgUnits:
			- engineering
			- marketing
			commonName: 1692387475-0dgrf.venafi.example.com
	installations:
		- format: PEM
		  file: '{{- Env "PWD" }}/tmp/aruba/c1.cer'
		  chainFile: '{{- Env "PWD" }}/tmp/aruba/ch1.cer'
		  keyFile: '{{- Env "PWD" }}/tmp/aruba/k1.pem'
		  afterInstallAction: echo SuccessInstall
```

If you want to find this generated file during debugging, aruba automatically
adds it to `/tmp/aruba/file_name.yml`; of course, assuming you are launching tests
from your IDE and not for Docker.

### Executing and validating the output

Continuing the previous steps:

13. We will now execute VCert with our YAML:

```
And I run `vcert run -f <config-file>`
```

14. And then start validating:

We validate output:

```
Then the output should contain "successfully executed after-install actions"
And the output should contain "playbook run finished"
```

We validate file exists:

```
And a file named "cert.cer" should exist
And a file named "chain.cer" should exist
And a file named "key.pem" should exist
```

We validate that files meet our expectations:

```
And playbook generated private key in "k1.pem" and certificate in "c1.cer" should have the same modulus
And "k1.pem" should not be encrypted RSA private key
And "k1.pem" should be RSA private key with password ""
```

### Removing generated files

Although if you are re-using the name of the YAML file Aruba will overwrite it
on every test, It's always good practice removing these files at the end of every test.

15. we remove the files we created:
```
And I uninstall file named "c1.cer"
And I uninstall file named "ch1.cer"
And I uninstall file named "k1.pem"
```

## RubyMine Setup

1. building the app every scenario run

	Run -> Edit Configurations... 
	
	Templates -> Cucumber

	Add Before launch: External tool
	
		Program: /usr/local/go/bin/go
		Arguments: build -o bin/vcert ../cmd/vcert
		Working directory: $GOPATH/src/github.com/Venafi/vcert/v4/aruba
	
	OK -> OK -> Apply -> OK


2. setting up local variables so that real-run scenarios knocks to real endpoints from IDE:

	$ vi aruba/features/step_definitions/0.endpoints.rb

		ENV['TPP_URL']      = "https://tpp.venafi.example.com:5008/vedsdk"
		ENV['TPP_USER']     = "user"
		ENV['TPP_PASSWORD'] = "xxx"
		ENV['TPP_ZONE']     = 'some\zone'
		ENV['CLOUD_URL']    = "https://api.venafi.example.com/v1"
		ENV['CLOUD_APIKEY']    = "xxxxxxxx-b256-4c43-a4d4-15372ce2d548"
		ENV['CLOUD_ZONE']   = "Default"
