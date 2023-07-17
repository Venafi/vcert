package certrequest

import (
	"fmt"
	"reflect"
	"testing"

	"github.com/stretchr/testify/suite"
)

type LocationSuite struct {
	suite.Suite
	testCases []struct {
		name       string
		instance   string
		workload   string
		tlsAddress string
	}
}

func (s *LocationSuite) SetupTest() {
	s.testCases = []struct {
		name       string
		instance   string
		workload   string
		tlsAddress string
	}{
		{name: "Instance", instance: "foo", workload: "", tlsAddress: "something"},
		{name: "InstanceWorkload", instance: "bar", workload: "foo", tlsAddress: "something"},
	}
}

func TestLocation(t *testing.T) {
	suite.Run(t, new(LocationSuite))
}

func (s *LocationSuite) TestLocation_toVCert() {

	for _, tc := range s.testCases {
		s.Run(tc.name, func() {
			location := Location{
				Instance:   fmt.Sprintf("%s:%s", tc.instance, tc.workload),
				TLSAddress: tc.tlsAddress,
			}

			vcertLocation := location.ToVCert()
			typ := reflect.TypeOf(*vcertLocation)
			s.Equal("github.com/Venafi/vcert/v4/pkg/certificate", typ.PkgPath())

			s.Equal(tc.instance, vcertLocation.Instance)
			s.Equal(tc.workload, vcertLocation.Workload)
			s.Equal(tc.tlsAddress, vcertLocation.TLSAddress)
		})
	}

	s.Run("Empty", func() {
		location := Location{}
		vcertLocation := location.ToVCert()
		s.Nil(vcertLocation)
	})
}
