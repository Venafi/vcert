package domain

import (
	"testing"

	"github.com/stretchr/testify/suite"
)

type AuthenticationSuite struct {
	suite.Suite
}

func (s *AuthenticationSuite) SetupTest() {

}

func TestAuthentication(t *testing.T) {
	suite.Run(t, new(AuthenticationSuite))
}

func (s *AuthenticationSuite) TestAuthentication_IsEmpty() {
	auth := Authentication{}
	result := auth.IsEmpty()
	s.True(result)
}
