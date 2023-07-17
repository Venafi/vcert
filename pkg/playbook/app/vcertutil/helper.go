package vcertutil

import (
	"fmt"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"

	"go.uber.org/zap"

	vreq "github.com/Venafi/vcert/v4/pkg/certificate"
	"github.com/Venafi/vcert/v4/pkg/playbook/app/domain/certrequest"
	"github.com/Venafi/vcert/v4/pkg/util"
)

const (
	// DefaultRSALength represents the default length of an RSA Private Key
	DefaultRSALength = 2048
	// OriginName represents the Origin of the Request set in a Custom Field
	OriginName = "Venafi VCertplus "
)

func loadTrustBundle(path string) string {
	if path != "" {
		buf, err := os.ReadFile(path)
		if err != nil {
			zap.L().Fatal(fmt.Sprintf("could not read TrustBundle at %s: %s", path, err.Error()))
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
			zap.L().Error(fmt.Sprintf("could not parse URI %s: %s", uriStr, err.Error()))
			continue
		}
		urls = append(urls, uri)
	}
	return urls
}

func setKeyType(request certrequest.Request, vcertRequest *vreq.Request) {
	switch request.KeyType {
	case certrequest.KeyTypeRSA:
		vcertRequest.KeyType = request.KeyType.ToVCert()
		if request.KeyLength <= 0 {
			vcertRequest.KeyLength = DefaultRSALength
		} else {
			vcertRequest.KeyLength = request.KeyLength
		}
	case certrequest.KeyTypeECDSA:
		vcertRequest.KeyType = request.KeyType.ToVCert()
		vcertRequest.KeyCurve = request.KeyCurve.ToVCert()
	default:
		vcertRequest.KeyType = vreq.KeyTypeRSA
		vcertRequest.KeyLength = DefaultRSALength
	}
}

func setOrigin(request certrequest.Request, vcertRequest *vreq.Request) {
	origin := OriginName
	if request.Origin != "" {
		origin = request.Origin
	}
	originCustomField := vreq.CustomField{
		Name:  "Origin",
		Value: origin,
		Type:  vreq.CustomFieldOrigin,
	}
	vcertRequest.CustomFields = append(vcertRequest.CustomFields, originCustomField)

}

func setValidity(validDays string, vcertRequest *vreq.Request) {
	if validDays == "" {
		return
	}

	data := strings.Split(validDays, "#")
	days, _ := strconv.ParseInt(data[0], 10, 64)
	hours := days * 24

	vcertRequest.ValidityHours = int(hours)

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
}
