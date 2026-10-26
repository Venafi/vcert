package endpoint

import (
	"crypto/x509/pkix"
	"testing"

	"github.com/Venafi/vcert/v5/pkg/certificate"
)

func mldsaTestPolicy(allowed ...AllowedKeyConfiguration) *Policy {
	return &Policy{
		SubjectCNRegexes:         []string{".*"},
		SubjectORegexes:          []string{".*"},
		SubjectOURegexes:         []string{".*"},
		SubjectSTRegexes:         []string{".*"},
		SubjectLRegexes:          []string{".*"},
		SubjectCRegexes:          []string{".*"},
		DnsSanRegExs:             []string{".*"},
		AllowedKeyConfigurations: allowed,
	}
}

var testSubject = pkix.Name{CommonName: "pqc.vcert.test", Organization: []string{"Venafi"}, OrganizationalUnit: []string{"Eng"},
	Country: []string{"US"}, Province: []string{"Utah"}, Locality: []string{"SLC"}}

func TestMLDSAValidateCertificateRequestFromCSR(t *testing.T) {
	for _, strength := range certificate.AllSupportedMLDSAStrengths() {
		req := &certificate.Request{Subject: testSubject, KeyType: certificate.KeyTypeMLDSA, KeyLength: strength}
		if err := req.GeneratePrivateKey(); err != nil {
			t.Fatal(err)
		}
		if err := req.GenerateCSR(); err != nil {
			t.Fatal(err)
		}
		csrOnly := &certificate.Request{Subject: testSubject}
		if err := csrOnly.SetCSR(req.GetCSR()); err != nil {
			t.Fatal(err)
		}

		allowed := mldsaTestPolicy(AllowedKeyConfiguration{KeyType: certificate.KeyTypeMLDSA, KeySizes: []int{strength}})
		if err := allowed.ValidateCertificateRequest(csrOnly); err != nil {
			t.Fatalf("ML-DSA-%d CSR should be accepted: %s", strength, err)
		}
		other := 44
		if strength == 44 {
			other = 87
		}
		denied := mldsaTestPolicy(
			AllowedKeyConfiguration{KeyType: certificate.KeyTypeRSA, KeySizes: []int{2048}},
			AllowedKeyConfiguration{KeyType: certificate.KeyTypeMLDSA, KeySizes: []int{other}},
		)
		if err := denied.ValidateCertificateRequest(csrOnly); err == nil {
			t.Fatalf("ML-DSA-%d CSR should be rejected by a policy that only allows ML-DSA-%d", strength, other)
		}
	}
}

func TestMLDSAValidateCertificateRequestFromFields(t *testing.T) {
	req := &certificate.Request{Subject: testSubject, KeyType: certificate.KeyTypeMLDSA, KeyLength: 65}
	if err := mldsaTestPolicy(AllowedKeyConfiguration{KeyType: certificate.KeyTypeMLDSA, KeySizes: []int{44, 65}}).ValidateCertificateRequest(req); err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	if err := mldsaTestPolicy(AllowedKeyConfiguration{KeyType: certificate.KeyTypeRSA, KeySizes: []int{2048}}).ValidateCertificateRequest(req); err == nil {
		t.Fatal("ML-DSA should be rejected by an RSA-only policy")
	}
}

func TestED25519ValidateCertificateRequestFromCSR(t *testing.T) {
	req := &certificate.Request{Subject: testSubject, KeyType: certificate.KeyTypeED25519, KeyCurve: certificate.EllipticCurveED25519}
	if err := req.GeneratePrivateKey(); err != nil {
		t.Fatal(err)
	}
	if err := req.GenerateCSR(); err != nil {
		t.Fatal(err)
	}
	policy := mldsaTestPolicy(AllowedKeyConfiguration{KeyType: certificate.KeyTypeECDSA, KeyCurves: []certificate.EllipticCurve{certificate.EllipticCurveED25519}})
	if err := policy.ValidateCertificateRequest(req); err != nil {
		t.Fatalf("Ed25519 CSR should be accepted: %s", err)
	}
}

func TestMLDSAUpdateCertificateRequestRecommendedStrength(t *testing.T) {
	z := NewZoneConfiguration()
	z.KeyConfiguration = &AllowedKeyConfiguration{KeyType: certificate.KeyTypeMLDSA, KeySizes: []int{65}}
	req := &certificate.Request{KeyType: certificate.KeyTypeMLDSA}
	z.UpdateCertificateRequest(req)
	if req.KeyLength != 65 {
		t.Fatalf("expected the recommended strength 65, got %d", req.KeyLength)
	}
	req = &certificate.Request{KeyType: certificate.KeyTypeMLDSA, KeyLength: 44}
	z.UpdateCertificateRequest(req)
	if req.KeyLength != 44 {
		t.Fatalf("an explicit strength must be kept, got %d", req.KeyLength)
	}
}

func TestDefaultMLDSAStrength(t *testing.T) {
	z := NewZoneConfiguration()
	if got := z.DefaultMLDSAStrength(); got != 0 {
		t.Fatalf("a zone without ML-DSA has no default strength, got %d", got)
	}
	z.AllowedKeyConfigurations = []AllowedKeyConfiguration{
		{KeyType: certificate.KeyTypeRSA, KeySizes: []int{2048}},
		{KeyType: certificate.KeyTypeMLDSA, KeySizes: []int{87, 44, 65}},
	}
	if got := z.DefaultMLDSAStrength(); got != 44 {
		t.Fatalf("expected the lowest allowed strength 44, got %d", got)
	}
	z.KeyConfiguration = &AllowedKeyConfiguration{KeyType: certificate.KeyTypeRSA, KeySizes: []int{2048}}
	if got := z.DefaultMLDSAStrength(); got != 44 {
		t.Fatalf("an RSA recommendation must not hide the allowed ML-DSA strengths, got %d", got)
	}
	z.KeyConfiguration = &AllowedKeyConfiguration{KeyType: certificate.KeyTypeMLDSA, KeySizes: []int{65}}
	if got := z.DefaultMLDSAStrength(); got != 65 {
		t.Fatalf("expected the recommended strength 65, got %d", got)
	}
}
