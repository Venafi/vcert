package caaccounts

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/Venafi/vcert/v5/pkg/webclient/caaccounts/mocks"
	"github.com/Venafi/vcert/v5/pkg/webclient/caaccounts/service"
)

//go:generate go run go.uber.org/mock/mockgen -destination=./mocks/mock_caaccounts.go -package=mocks -source=./service/service.go

func TestListCAAccounts(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		mockCtrl := gomock.NewController(t)
		defer mockCtrl.Finish()

		caAccountExpected := &service.ListCAAccountsCertificateAuthorityAccountsCertificateAuthorityAccountConnectionNodesCertificateAuthorityAccount{
			Id:                       "myId",
			Name:                     "myName",
			CertificateAuthorityType: service.CertificateAuthorityTypeMicrosoft,
		}

		listCAAccountsResponse := &service.ListCAAccountsResponse{
			CertificateAuthorityAccounts: &service.ListCAAccountsCertificateAuthorityAccountsCertificateAuthorityAccountConnection{
				Nodes: []*service.ListCAAccountsCertificateAuthorityAccountsCertificateAuthorityAccountConnectionNodesCertificateAuthorityAccount{
					caAccountExpected,
				},
			},
		}

		caAccountService := mocks.NewMockCAAccountsServiceWrapper(mockCtrl)
		caAccountService.EXPECT().ListCAAccounts(context.Background()).Return(listCAAccountsResponse, nil)

		caAccountsClient := NewCAAccountsClient("", nil)
		//replacing the default CAAccountsService instance by the mock
		caAccountsClient.SetCAAccountsService(caAccountService)

		accounts, err := caAccountsClient.ListCAAccounts(context.Background())
		require.NoError(t, err)
		require.NotEmpty(t, accounts)
		require.Equal(t, 1, len(accounts))
		caAccountResult, ok := accounts[caAccountExpected.GetName()]
		require.True(t, ok)
		require.Equal(t, caAccountExpected.GetId(), caAccountResult.Id)
		require.Equal(t, string(caAccountExpected.CertificateAuthorityType), caAccountResult.CertificateAuthorityType)
	})
	t.Run("empty", func(t *testing.T) {
		mockCtrl := gomock.NewController(t)
		defer mockCtrl.Finish()

		listCAAccountsResponse := &service.ListCAAccountsResponse{
			CertificateAuthorityAccounts: &service.ListCAAccountsCertificateAuthorityAccountsCertificateAuthorityAccountConnection{
				Nodes: []*service.ListCAAccountsCertificateAuthorityAccountsCertificateAuthorityAccountConnectionNodesCertificateAuthorityAccount{},
			},
		}

		caAccountService := mocks.NewMockCAAccountsServiceWrapper(mockCtrl)
		caAccountService.EXPECT().ListCAAccounts(context.Background()).Return(listCAAccountsResponse, nil)

		caAccountsClient := NewCAAccountsClient("", nil)
		//replacing the default CAAccountsService instance by the mock
		caAccountsClient.SetCAAccountsService(caAccountService)

		accounts, err := caAccountsClient.ListCAAccounts(context.Background())
		require.NoError(t, err)
		require.Empty(t, accounts)
	})
	t.Run("error", func(t *testing.T) {
		mockCtrl := gomock.NewController(t)
		defer mockCtrl.Finish()

		expectedError := errors.New("expected error")

		caAccountService := mocks.NewMockCAAccountsServiceWrapper(mockCtrl)
		caAccountService.EXPECT().ListCAAccounts(context.Background()).Return(nil, expectedError)

		caAccountsClient := NewCAAccountsClient("", nil)
		//replacing the default CAAccountsService instance by the mock
		caAccountsClient.SetCAAccountsService(caAccountService)

		accounts, err := caAccountsClient.ListCAAccounts(context.Background())
		require.Error(t, err)
		require.Equal(t, expectedError, err)
		require.Empty(t, accounts)
	})
}
