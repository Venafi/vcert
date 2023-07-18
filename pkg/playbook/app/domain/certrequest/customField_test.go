package certrequest

import (
	"reflect"
	"testing"

	"github.com/stretchr/testify/suite"
)

type CustomFieldSuite struct {
	suite.Suite
}

func (s *CustomFieldSuite) SetupTest() {

}

func TestCustomField(t *testing.T) {
	suite.Run(t, new(CustomFieldSuite))
}

func (s *CustomFieldSuite) TestCustomField_toVCert() {
	cf := CustomField{
		Type:  CFTypeOrigin,
		Name:  "foo",
		Value: "bar",
	}

	vcertCf := cf.ToVCert()
	typ := reflect.TypeOf(vcertCf)
	s.Equal("github.com/Venafi/vcert/v4/pkg/certificate", typ.PkgPath())
}

func (s *CustomFieldSuite) TestCustomFields_toVCert() {
	s.Run("Empty", func() {
		cfs := CustomFields{}
		vcertCfs := cfs.ToVCert()
		s.Nil(vcertCfs)
	})

	s.Run("NotEmpty", func() {
		cfs := CustomFields{
			{
				Type:  CFTypePlain,
				Name:  "foo",
				Value: "bar",
			},
		}
		vcertCfs := cfs.ToVCert()
		typ := reflect.TypeOf(vcertCfs[0])
		s.Equal("github.com/Venafi/vcert/v4/pkg/certificate", typ.PkgPath())
	})
}
