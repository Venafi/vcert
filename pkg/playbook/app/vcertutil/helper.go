/*
 * Copyright 2023 Venafi, Inc.
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

package vcertutil

import (
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"go.uber.org/zap"

	"github.com/Venafi/vcert/v4/pkg/certificate"
	"github.com/Venafi/vcert/v4/pkg/playbook/app/domain"
	"github.com/Venafi/vcert/v4/pkg/util"
)

const (
	// DefaultRSALength represents the default length of an RSA Private Key
	DefaultRSALength = 2048

	// DefaultTimeout represents the default time in seconds vcert will try to retrieve a certificate
	DefaultTimeout = 180

	// OriginName represents the Origin of the Request set in a Custom Field
	OriginName = "Venafi VCertplus"
)

func loadTrustBundle(path string) string {
	if path != "" {
		buf, err := os.ReadFile(path)
		if err != nil {
			zap.L().Fatal("could not read TrustBundle", zap.String("location", path), zap.Error(err))
		}
		return string(buf)
	}
	return ""
}

func getIPAddresses(ips []string) []net.IP {
	netIps := make([]net.IP, 0)
	for _, ipStr := range ips {
		ip := net.ParseIP(ipStr)
		if ip != nil {
			netIps = append(netIps, ip)
		}
	}
	return netIps
}

func getURIs(uris []string) []*url.URL {
	urls := make([]*url.URL, 0)

	for _, uriStr := range uris {
		uri, err := url.Parse(uriStr)
		if err != nil {
			zap.L().Error("could not parse URI", zap.String("uri", uriStr), zap.Error(err))
			continue
		}
		urls = append(urls, uri)
	}
	return urls
}

func setKeyType(request domain.PlaybookRequest, vcertRequest *certificate.Request) {
	switch request.KeyType {
	case certificate.KeyTypeRSA:
		vcertRequest.KeyType = request.KeyType
		if request.KeyLength <= 0 {
			vcertRequest.KeyLength = DefaultRSALength
		} else {
			vcertRequest.KeyLength = request.KeyLength
		}
	case certificate.KeyTypeECDSA:
		vcertRequest.KeyType = request.KeyType
		vcertRequest.KeyCurve = request.KeyCurve
	case certificate.KeyTypeED25519:
		vcertRequest.KeyType = request.KeyType
		vcertRequest.KeyCurve = certificate.EllipticCurveED25519
	default:
		vcertRequest.KeyType = certificate.KeyTypeRSA
		vcertRequest.KeyLength = DefaultRSALength
	}
}

func setOrigin(request domain.PlaybookRequest, vcertRequest *certificate.Request) {
	origin := OriginName
	if request.Origin != "" {
		origin = request.Origin
	}
	originCustomField := certificate.CustomField{
		Name:  "Origin",
		Value: origin,
		Type:  certificate.CustomFieldOrigin,
	}
	vcertRequest.CustomFields = append(vcertRequest.CustomFields, originCustomField)

}

func setValidity(request domain.PlaybookRequest, vcertRequest *certificate.Request) {
	if request.ValidDays == "" {
		return
	}

	data := strings.Split(request.ValidDays, "#")
	days, _ := strconv.ParseInt(data[0], 10, 64)
	hours := days * 24

	vcertRequest.ValidityHours = int(hours) //nolint:staticcheck

	var issuerHint util.IssuerHint
	if len(data) > 1 { // means that issuer hint is set
		option := strings.ToLower(data[1])
		switch option {
		case "m":
			issuerHint = util.IssuerHintMicrosoft
		case "d":
			issuerHint = util.IssuerHintDigicert
		case "e":
			issuerHint = util.IssuerHintEntrust
		}
	}
	vcertRequest.IssuerHint = issuerHint

	// If IssuerHint is declared in playbook, override issuerHint from validDays string
	if request.IssuerHint != util.IssuerHintGeneric {
		vcertRequest.IssuerHint = request.IssuerHint
	}
}

func setLocationWorkload(playbookRequest domain.PlaybookRequest, vcertRequest *certificate.Request) {
	if playbookRequest.Location.Instance == "" {
		return
	}

	segments := strings.Split(playbookRequest.Location.Instance, ":")
	instance := segments[0]
	workload := ""
	// take workload from instance string
	if len(segments) > 1 {
		workload = segments[1]
	}
	// take workload from attribute.
	// workload attribute has priority over workload string declared in request.Location.Instance
	if playbookRequest.Location.Workload != "" {
		workload = playbookRequest.Location.Workload
	}

	newLocation := certificate.Location{
		Instance:   instance,
		Workload:   workload,
		TLSAddress: playbookRequest.Location.TLSAddress,
		Replace:    playbookRequest.Location.Replace,
	}
	vcertRequest.Location = &newLocation
}

func setTimeout(playbookRequest domain.PlaybookRequest, vcertRequest *certificate.Request) {
	timeout := DefaultTimeout
	if playbookRequest.Timeout > 0 {
		timeout = playbookRequest.Timeout
	}
	vcertRequest.Timeout = time.Duration(timeout) * time.Second
}
