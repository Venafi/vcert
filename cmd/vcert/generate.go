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

package main

import (
	"encoding/pem"
	"fmt"
	"github.com/Venafi/vcert"
	"github.com/Venafi/vcert/pkg/certificate"
	"os"
)

func setupGenCsrCommandFlags() {
	genCsrFlags.Var(&genCsrParams.keyCurve, "key-curve", "")
	genCsrFlags.Var(&genCsrParams.keyType, "key-type", "")
	genCsrFlags.IntVar(&genCsrParams.keySize, "key-size", 2048, "")
	genCsrFlags.StringVar(&genCsrParams.keyPassword, "key-password", "", "")
	genCsrFlags.StringVar(&genCsrParams.commonName, "cn", "", "")
	genCsrFlags.StringVar(&genCsrParams.org, "o", "", "")
	genCsrFlags.StringVar(&genCsrParams.state, "st", "", "")
	genCsrFlags.StringVar(&genCsrParams.country, "c", "", "")
	genCsrFlags.StringVar(&genCsrParams.locality, "l", "", "")
	genCsrFlags.Var(&genCsrParams.orgUnits, "ou", "")
	genCsrFlags.Var(&genCsrParams.dnsSans, "san-dns", "")
	genCsrFlags.Var(&genCsrParams.ipSans, "san-ip", "")
	genCsrFlags.Var(&genCsrParams.emailSans, "san-email", "")
	genCsrFlags.StringVar(&genCsrParams.keyFile, "key-file", "", "")
	genCsrFlags.StringVar(&genCsrParams.csrFile, "csr-file", "", "")
	genCsrFlags.BoolVar(&genCsrParams.verbose, "verbose", false, "")
	genCsrFlags.BoolVar(&genCsrParams.noPrompt, "no-prompt", false, "")

	genCsrFlags.Usage = func() {
		fmt.Printf("%s\n", vcert.GetFormattedVersionString())
		showGenerateUsage()
	}
}

func showGenerateUsage() {
	fmt.Printf("Generate Certificate Signing Request Usage:\n")
	fmt.Printf("  %s gencsr <Required><Options>\n", os.Args[0])
	fmt.Printf("  %s gencsr -cn <common name> -o <organization> -ou <organizational unit> -c <country> -st <state> -l <locality> -key-file <key output file> -csr-file <csr output file>\n", os.Args[0])
	fmt.Printf("  %s gencsr -cn <common name> -o <organization> -ou <organizational unit> -ou <organizational unit2> -c <country> -st <state> -l <locality> -key-file <key output file> -csr-file <csr output file>\n", os.Args[0])
	fmt.Println()
	fmt.Printf("Required: One of the following must be supplied\n")
	fmt.Println("  -cn")
	fmt.Printf("\t%s\n", wrapArgumentDescriptionText("Use to specify the common name (CN)."))
	fmt.Println("  -san-dns")
	fmt.Printf("\t%s\n", wrapArgumentDescriptionText("Use to specify one or more DNS Subject Alternative Name. Example: -san-dns test.abc.xyz -san-dns test1.abc.xyz"))

	fmt.Printf("\nOptions:\n")
	fmt.Println("  -key-type")
	fmt.Printf("\t%s\n", wrapArgumentDescriptionText("Use to specify a key type. Options include: rsa (default) | ecdsa"))
	fmt.Println("  -key-curve value")
	fmt.Printf("\t%s\n", wrapArgumentDescriptionText("Use to specify the ECDSA key curve. Options include: p521 | p384 | p256 (default p521)"))
	fmt.Println("  -o")
	fmt.Printf("\t%s\n", wrapArgumentDescriptionText("Use to specify the organization name (O)."))
	fmt.Println("  -ou")
	fmt.Printf("\t%s\n", wrapArgumentDescriptionText("Use to specify one or more organizational unit (OU). Example: -ou Ounit1 -ou Ounit2"))
	fmt.Println("  -c")
	fmt.Printf("\t%s\n", wrapArgumentDescriptionText("Use to specify the country (C)."))
	fmt.Println("  -st")
	fmt.Printf("\t%s\n", wrapArgumentDescriptionText("Use to specify the state/province (ST)."))
	fmt.Println("  -l")
	fmt.Printf("\t%s\n", wrapArgumentDescriptionText("Use to specify the locality (L)."))
	fmt.Println("  -no-prompt")
	fmt.Printf("\t%s\n", wrapArgumentDescriptionText("Use to exclude the authentication prompt. If you enable the prompt and you enter incorrect information, an error is displayed. This is useful with scripting."))
	fmt.Println("  -san-email")
	fmt.Printf("\t%s\n", wrapArgumentDescriptionText("Use to specify aone or more Email Subject Alternative Name.  Example: -san-email abc@abc.xyz -san-email def@abc.xyz"))
	fmt.Println("  -san-ip")
	fmt.Printf("\t%s\n", wrapArgumentDescriptionText("Use to specify one or more IP Address Subject Alternative Name.  Example: -san-ip 1.1.1.1 -san-ip 2.2.2.2"))
	fmt.Println("  -verbose")
	fmt.Printf("\t%s\n", wrapArgumentDescriptionText("Use to increase the level of logging detail, which is helpful when troubleshooting issues"))
	fmt.Println("  -key-password")
	fmt.Printf("\t%s\n", wrapArgumentDescriptionText("Use to specify a password for encrypting the private key. For a non-encrypted private key, specify -no-prompt without specifying this option. You can specify the password using one of three methods: at the command line, when prompted, or by using a password file. Example: -key-password file:/Temp/mypasswrds.txt"))
	fmt.Println("  -key-file")
	fmt.Printf("\t%s\n", wrapArgumentDescriptionText("Use to specify a file name and a location where the resulting key file should be written. Example: /tmp/newkey.pem"))
	fmt.Println("  -csr-file")
	fmt.Printf("\t%s\n", wrapArgumentDescriptionText("Use to specify a file name and a location where the resulting CSR file should be written. Example: /tmp/newcsr.pem"))
	fmt.Println("  -h")
	fmt.Printf("\t%s\n", wrapArgumentDescriptionText("Use to show the help text."))
	fmt.Println()
}

func validateGenerateFlags() error {
	switch genCsrParams.keyType {
	case certificate.KeyTypeRSA:
		if genCsrParams.keySize < 1024 {
			return fmt.Errorf("Key Size must be 1024 or greater")
		}
	case certificate.KeyTypeECDSA:
	}
	if genCsrParams.commonName == "" && len(genCsrParams.dnsSans) == 0 {
		return fmt.Errorf("A Common Name (cn) or Subject Alternative Name: DNS (san-dns) value is required")
	}

	return nil
}

func generateCsrForCommandGenCsr(cf *commandFlags, privateKeyPass []byte) (privateKey []byte, csr []byte, err error) {
	var generatedKey interface{}
	switch cf.keyType {
	case certificate.KeyTypeRSA:
		generatedKey, err = certificate.GenerateRSAPrivateKey(cf.keySize)
		break
	case certificate.KeyTypeECDSA:
		generatedKey, err = certificate.GenerateECDSAPrivateKey(cf.keyCurve)
		break
	default:
		err = fmt.Errorf("Unknown key type: %s", string(cf.keyType))
		return
	}
	if err != nil {
		return
	}

	var pBlock *pem.Block
	if privateKeyPass == nil || len(privateKeyPass) == 0 {
		pBlock, err = certificate.GetPrivateKeyPEMBock(generatedKey)
		if err != nil {
			return
		}
		privateKey = pem.EncodeToMemory(pBlock)
	} else {
		pBlock, err = certificate.GetEncryptedPrivateKeyPEMBock(generatedKey, privateKeyPass)
		if err != nil {
			return
		}
		privateKey = pem.EncodeToMemory(pBlock)
	}
	certReq := &certificate.Request{}
	certReq = fillCertificateRequest(certReq, cf)
	err = certificate.GenerateRequest(certReq, generatedKey)
	if err != nil {
		return
	}
	pBlock = certificate.GetCertificateRequestPEMBlock(certReq.CSR)
	csr = pem.EncodeToMemory(pBlock)

	return
}

func writeOutKeyAndCsr(cf *commandFlags, key []byte, csr []byte) error {
	var err error

	switch {
	case cf.keyFile != "" && cf.csrFile != "":
		keyWriter := getFileWriter(cf.keyFile)
		keyFile, ok := keyWriter.(*os.File)
		if ok {
			defer keyFile.Close()
		}
		csrWriter := getFileWriter(cf.csrFile)
		csrFile, ok := csrWriter.(*os.File)
		if ok {
			defer csrFile.Close()
		}

		_, err = keyWriter.Write(key)
		if err != nil {
			return err
		}
		_, err = csrWriter.Write(csr)
		if err != nil {
			return err
		}
	case cf.file != "":
		writer := getFileWriter(cf.file)
		f, ok := writer.(*os.File)
		if ok {
			defer f.Close()
		}

		_, err = writer.Write(key)
		if err != nil {
			return err
		}
		_, err = writer.Write(csr)
		if err != nil {
			return err
		}
	default:
		writer := getFileWriter("")
		f, ok := writer.(*os.File)
		if ok {
			defer f.Close()
		}

		_, err = writer.Write(key)
		if err != nil {
			return err
		}
		_, err = writer.Write(csr)
		if err != nil {
			return err
		}
	}
	return nil
}
