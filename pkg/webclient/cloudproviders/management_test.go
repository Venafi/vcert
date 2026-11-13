package cloudproviders

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/Venafi/vcert/v5/pkg/domain"
	"github.com/Venafi/vcert/v5/pkg/verror"
)

type graphqlRequest struct {
	OperationName string                 `json:"operationName"`
	Variables     map[string]interface{} `json:"variables"`
}

// newTestClient returns a client whose GraphQL server answers each request
// with the next of the given response bodies, and records the requests it got
func newTestClient(t *testing.T, responses ...string) (*CloudProvidersClient, *[]graphqlRequest) {
	t.Helper()
	requests := make([]graphqlRequest, 0)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		var req graphqlRequest
		require.NoError(t, json.Unmarshal(body, &req))
		requests = append(requests, req)

		require.Less(t, len(requests)-1, len(responses), "unexpected request %s", req.OperationName)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(responses[len(requests)-1]))
	}))
	t.Cleanup(server.Close)
	return NewCloudProvidersClient(server.URL, server.Client()), &requests
}

func strPtr(s string) *string { return &s }

func boolPtr(b bool) *bool { return &b }

func TestListCloudProvidersFollowsPages(t *testing.T) {
	client, requests := newTestClient(t,
		`{"data":{"cloudProviders":{"nodes":[{"id":"p1","name":"one","type":"AWS","status":"VALIDATED","keystoresCount":2}],
			"pageInfo":{"hasNextPage":true,"endCursor":"c1"}}}}`,
		`{"data":{"cloudProviders":{"nodes":[{"id":"p2","name":"two","type":"GCP","status":"NOT_VALIDATED","statusDetails":"bad key","keystoresCount":0}],
			"pageInfo":{"hasNextPage":false,"endCursor":"c2"}}}}`,
	)

	providers, err := client.ListCloudProviders(context.Background(), domain.GetCloudProviderRequest{Type: domain.CloudProviderTypeAWS})
	require.NoError(t, err)

	require.Len(t, providers, 2)
	assert.Equal(t, domain.CloudProvider{ID: "p1", Name: "one", Type: domain.CloudProviderTypeAWS, Status: domain.CloudProviderStatusValidated, KeystoresCount: 2}, providers[0])
	assert.Equal(t, domain.CloudProvider{ID: "p2", Name: "two", Type: domain.CloudProviderTypeGCP, Status: domain.CloudProviderStatusNotValidated, StatusDetails: "bad key"}, providers[1])

	require.Len(t, *requests, 2)
	assert.Equal(t, "AWS", (*requests)[0].Variables["providerType"])
	assert.Nil(t, (*requests)[0].Variables["after"])
	assert.Equal(t, "c1", (*requests)[1].Variables["after"])
}

func TestListCloudProvidersStopsOnARepeatedCursor(t *testing.T) {
	page := `{"data":{"cloudProviders":{"nodes":[{"id":"p1","name":"one","type":"AWS","status":"VALIDATED","keystoresCount":0}],
		"pageInfo":{"hasNextPage":true,"endCursor":"c1"}}}}`
	client, requests := newTestClient(t, page, page)

	_, err := client.ListCloudProviders(context.Background(), domain.GetCloudProviderRequest{})
	require.ErrorContains(t, err, `same page cursor "c1"`)
	assert.Len(t, *requests, 2)
}

func TestListCloudProvidersConvertsConfiguration(t *testing.T) {
	client, _ := newTestClient(t,
		`{"data":{"cloudProviders":{"nodes":[
			{"id":"p1","name":"aws","type":"AWS","status":"VALIDATED","keystoresCount":0,
			 "configuration":{"__typename":"CloudProviderAWSConfiguration","accountId":"123456789012","role":"role","externalId":"ext-1"}},
			{"id":"p2","name":"azure","type":"AZURE","status":"VALIDATED","keystoresCount":0,
			 "configuration":{"__typename":"CloudProviderAzureConfiguration","applicationId":"app","directoryId":"dir"}},
			{"id":"p3","name":"gcp","type":"GCP","status":"NOT_VALIDATED","keystoresCount":0,
			 "configuration":{"__typename":"CloudProviderGCPConfiguration","serviceAccountEmail":"sa@p.iam.gserviceaccount.com",
			  "authorizationMethod":"VENAFI_GENERATED_KEY","publicKey":"-----BEGIN PUBLIC KEY-----","issuerUrl":"https://issuer"}},
			{"id":"p4","name":"akamai","type":"AKAMAI","status":"VALIDATED","keystoresCount":0,
			 "configuration":{"__typename":"CloudProviderAkamaiConfiguration"}}
		],"pageInfo":{"hasNextPage":false}}}}`,
	)

	providers, err := client.ListCloudProviders(context.Background(), domain.GetCloudProviderRequest{})
	require.NoError(t, err)
	require.Len(t, providers, 4)

	assert.Equal(t, &domain.CloudProviderAWSConfiguration{AccountID: "123456789012", Role: "role", ExternalID: "ext-1"}, providers[0].AWS)
	assert.Equal(t, &domain.CloudProviderAzureConfiguration{ApplicationID: "app", DirectoryID: "dir"}, providers[1].Azure)
	assert.Equal(t, &domain.CloudProviderGCPConfiguration{
		ServiceAccountEmail: "sa@p.iam.gserviceaccount.com",
		AuthorizationMethod: domain.GCPAuthorizationMethodVenafiGeneratedKey,
		PublicKey:           "-----BEGIN PUBLIC KEY-----",
		IssuerURL:           "https://issuer",
	}, providers[2].GCP)
	// unsupported provider types are listed without a configuration
	assert.Nil(t, providers[3].AWS)
	assert.Nil(t, providers[3].Azure)
	assert.Nil(t, providers[3].GCP)
}

func TestCreateCloudProviderSendsOnlyTheMatchingConfiguration(t *testing.T) {
	client, requests := newTestClient(t,
		`{"data":{"createCloudProvider":{"id":"p1","name":"azure","type":"AZURE","status":"NOT_VALIDATED","keystoresCount":0}}}`,
	)

	provider, err := client.CreateCloudProvider(context.Background(), domain.CreateCloudProviderRequest{
		Name:  "azure",
		Type:  domain.CloudProviderTypeAzure,
		Azure: &domain.CloudProviderAzureConfiguration{ApplicationID: "app", DirectoryID: "dir", Secret: "secret"},
	})
	require.NoError(t, err)
	assert.Equal(t, "p1", provider.ID)
	assert.Equal(t, domain.CloudProviderTypeAzure, provider.Type)

	input := (*requests)[0].Variables["input"].(map[string]interface{})
	assert.Equal(t, "AZURE", input["type"])
	assert.Equal(t, map[string]interface{}{"applicationId": "app", "directoryId": "dir", "secret": "secret"}, input["azureConfiguration"])
	assert.NotContains(t, input, "awsConfiguration")
	assert.NotContains(t, input, "gcpConfiguration")
}

func TestCreateCloudProviderOmitsUnsetFields(t *testing.T) {
	client, requests := newTestClient(t,
		`{"data":{"createCloudProvider":{"id":"p1","name":"gcp","type":"GCP","status":"NOT_VALIDATED","keystoresCount":0}}}`,
	)

	_, err := client.CreateCloudProvider(context.Background(), domain.CreateCloudProviderRequest{
		Name: "gcp",
		Type: domain.CloudProviderTypeGCP,
		GCP: &domain.CloudProviderGCPConfiguration{
			ServiceAccountEmail: "sa@project.iam.gserviceaccount.com",
			AuthorizationMethod: domain.GCPAuthorizationMethodVenafiGeneratedKey,
		},
	})
	require.NoError(t, err)

	// Fields that were not set must not be sent at all, not even as null
	input := (*requests)[0].Variables["input"].(map[string]interface{})
	assert.Equal(t, map[string]interface{}{
		"name": "gcp",
		"type": "GCP",
		"gcpConfiguration": map[string]interface{}{
			"serviceAccountEmail": "sa@project.iam.gserviceaccount.com",
			"authorizationMethod": "VENAFI_GENERATED_KEY",
		},
	}, input)
}

func TestCreateCloudProviderRejectsMissingConfiguration(t *testing.T) {
	client, requests := newTestClient(t)

	_, err := client.CreateCloudProvider(context.Background(), domain.CreateCloudProviderRequest{Name: "aws", Type: domain.CloudProviderTypeAWS})
	require.Error(t, err)
	assert.Empty(t, *requests)
}

func TestUpdateCloudProviderOmitsUnchangedFields(t *testing.T) {
	client, requests := newTestClient(t,
		`{"data":{"updateCloudProvider":{"id":"p1","name":"renamed","type":"AWS","status":"VALIDATED","keystoresCount":1}}}`,
	)

	_, err := client.UpdateCloudProvider(context.Background(), domain.UpdateCloudProviderRequest{
		ID:   "p1",
		Type: domain.CloudProviderTypeAWS,
		Name: strPtr("renamed"),
	})
	require.NoError(t, err)

	// Fields that were not set must not be sent at all, since an explicit null
	// could clear them on the server
	input := (*requests)[0].Variables["input"].(map[string]interface{})
	assert.Equal(t, map[string]interface{}{"id": "p1", "type": "AWS", "name": "renamed"}, input)
}

func TestUpdateCloudProviderRejectsConfigurationOfAnotherType(t *testing.T) {
	client, requests := newTestClient(t)

	_, err := client.UpdateCloudProvider(context.Background(), domain.UpdateCloudProviderRequest{
		ID:   "p1",
		Type: domain.CloudProviderTypeGCP,
		AWS:  &domain.CloudProviderAWSConfigurationUpdate{Role: strPtr("role")},
	})
	require.Error(t, err)
	assert.Empty(t, *requests)
}

func TestValidateCloudProvider(t *testing.T) {
	client, _ := newTestClient(t,
		`{"data":{"validateCloudProvider":{"result":"NOT_VALIDATED","details":"access denied"}}}`,
	)

	result, err := client.ValidateCloudProvider(context.Background(), "p1")
	require.NoError(t, err)
	assert.Equal(t, domain.CloudProviderValidationResult{Status: domain.CloudProviderStatusNotValidated, Details: "access denied"}, *result)
}

func TestDeleteCloudProviderFailsWhenNotDeleted(t *testing.T) {
	client, requests := newTestClient(t, `{"data":{"deleteCloudProvider":false}}`)

	err := client.DeleteCloudProvider(context.Background(), "p1")
	require.Error(t, err)
	assert.Equal(t, []interface{}{"p1"}, (*requests)[0].Variables["cloudProviderIds"])
}

func TestGraphQLErrorsArePropagated(t *testing.T) {
	client, _ := newTestClient(t, `{"data":null,"errors":[{"message":"permission denied"}]}`)

	err := client.DeleteCloudKeystore(context.Background(), "k1")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "permission denied")
}

const keystoreNodeJSON = `{
	"id":"k1","name":"vault","type":"AKV","machineIdentitiesCount":3,
	"cloudProvider":{"id":"p1","name":"azure"},
	"configuration":{"__typename":"CloudKeystoreAKVConfiguration","keyVaultName":"prod-vault"},
	"discoveryConfiguration":{"scheduleSpecification":"00 03 * * *","includeExpiredCertificates":true,"includeRevokedCertificates":false}
}`

func TestListCloudKeystoresConvertsDetails(t *testing.T) {
	client, requests := newTestClient(t,
		`{"data":{"cloudKeystores":{"nodes":[`+keystoreNodeJSON+`],"pageInfo":{"hasNextPage":false}}}}`,
	)

	keystores, err := client.ListCloudKeystores(context.Background(), domain.GetCloudKeystoreRequest{CloudProviderName: strPtr("azure")})
	require.NoError(t, err)
	require.Len(t, keystores, 1)

	k := keystores[0]
	assert.Equal(t, "k1", k.ID)
	assert.Equal(t, domain.CloudKeystoreTypeAKV, k.Type)
	assert.Equal(t, "p1", k.CloudProviderID)
	assert.Equal(t, "azure", k.CloudProviderName)
	assert.Equal(t, &domain.CloudKeystoreAKVConfiguration{KeyVaultName: "prod-vault"}, k.AKV)
	assert.Nil(t, k.ACM)
	assert.Equal(t, &domain.CloudDiscoveryConfiguration{ScheduleSpecification: "00 03 * * *", IncludeExpiredCertificates: true}, k.DiscoveryConfiguration)

	assert.Equal(t, "azure", (*requests)[0].Variables["cloudProviderName"])
	assert.Nil(t, (*requests)[0].Variables["cloudKeystoreId"])
}

func TestCreateCloudKeystore(t *testing.T) {
	client, requests := newTestClient(t, `{"data":{"createCloudKeystore":`+keystoreNodeJSON+`}}`)

	_, err := client.CreateCloudKeystore(context.Background(), domain.CreateCloudKeystoreRequest{
		Name:            "vault",
		Type:            domain.CloudKeystoreTypeAKV,
		CloudProviderID: "p1",
		AKV:             &domain.CloudKeystoreAKVConfiguration{KeyVaultName: "prod-vault"},
		Discovery:       &domain.CloudDiscoveryOptions{IncludeExpiredCertificates: boolPtr(false)},
	})
	require.NoError(t, err)

	input := (*requests)[0].Variables["input"].(map[string]interface{})
	assert.Equal(t, "AKV", input["type"])
	assert.Equal(t, "p1", input["cloudProviderId"])
	assert.Equal(t, map[string]interface{}{"keyVaultName": "prod-vault"}, input["akvConfiguration"])
	// false was set explicitly, so it must be sent; the other options were not
	assert.Equal(t, map[string]interface{}{"includeExpiredCertificates": false}, input["discoveryConfiguration"])
	// neither were the team or the sharing settings
	for _, field := range []string{"teamId", "authorizedTeams", "authorizedServiceAccounts", "allServiceAccountsAccess", "consumerTsgIds", "consumerWorkspaceIds"} {
		assert.NotContains(t, input, field)
	}
}

func TestCreateCloudKeystoreOmitsUnsetACMAccount(t *testing.T) {
	client, requests := newTestClient(t, `{"data":{"createCloudKeystore":`+keystoreNodeJSON+`}}`)

	_, err := client.CreateCloudKeystore(context.Background(), domain.CreateCloudKeystoreRequest{
		Name:            "acm",
		Type:            domain.CloudKeystoreTypeACM,
		CloudProviderID: "p1",
		TeamID:          "team-1",
		ACM:             &domain.CloudKeystoreACMConfiguration{Region: "us-east-2"},
	})
	require.NoError(t, err)

	input := (*requests)[0].Variables["input"].(map[string]interface{})
	assert.Equal(t, "team-1", input["teamId"])
	assert.Equal(t, map[string]interface{}{"region": "us-east-2"}, input["acmConfiguration"])
}

func keystoreListResponse(node string) string {
	return `{"data":{"cloudKeystores":{"nodes":[` + node + `],"pageInfo":{"hasNextPage":false}}}}`
}

func TestUpdateCloudKeystoreKeepsDiscoverySettings(t *testing.T) {
	// The API resets any discovery setting that is not sent, so a rename must
	// send the current ones: schedule "00 03 * * *", expired true, revoked false
	client, requests := newTestClient(t,
		keystoreListResponse(keystoreNodeJSON),
		`{"data":{"updateCloudKeystore":`+keystoreNodeJSON+`}}`,
	)

	_, err := client.UpdateCloudKeystore(context.Background(), domain.UpdateCloudKeystoreRequest{ID: "k1", Name: strPtr("renamed")})
	require.NoError(t, err)

	require.Len(t, *requests, 2)
	assert.Equal(t, "ListCloudKeystores", (*requests)[0].OperationName)
	assert.Equal(t, "k1", (*requests)[0].Variables["cloudKeystoreId"])
	input := (*requests)[1].Variables["input"].(map[string]interface{})
	assert.Equal(t, map[string]interface{}{
		"id":   "k1",
		"name": "renamed",
		"discoveryConfiguration": map[string]interface{}{
			"scheduleSpecification":      "00 03 * * *",
			"includeExpiredCertificates": true,
			"includeRevokedCertificates": false,
		},
	}, input)
}

func TestUpdateCloudKeystoreMergesDiscoveryChanges(t *testing.T) {
	client, requests := newTestClient(t,
		keystoreListResponse(keystoreNodeJSON),
		`{"data":{"updateCloudKeystore":`+keystoreNodeJSON+`}}`,
	)

	_, err := client.UpdateCloudKeystore(context.Background(), domain.UpdateCloudKeystoreRequest{
		ID:        "k1",
		Discovery: &domain.CloudDiscoveryOptions{IncludeRevokedCertificates: boolPtr(true)},
	})
	require.NoError(t, err)

	input := (*requests)[1].Variables["input"].(map[string]interface{})
	assert.Equal(t, map[string]interface{}{
		"scheduleSpecification":      "00 03 * * *",
		"includeExpiredCertificates": true,
		"includeRevokedCertificates": true,
	}, input["discoveryConfiguration"])
	assert.NotContains(t, input, "name")
}

func TestUpdateCloudKeystoreClearsSchedule(t *testing.T) {
	client, requests := newTestClient(t,
		keystoreListResponse(keystoreNodeJSON),
		`{"data":{"updateCloudKeystore":`+keystoreNodeJSON+`}}`,
	)

	_, err := client.UpdateCloudKeystore(context.Background(), domain.UpdateCloudKeystoreRequest{
		ID:        "k1",
		Discovery: &domain.CloudDiscoveryOptions{ScheduleSpecification: strPtr("")},
	})
	require.NoError(t, err)

	// The API deletes the schedule when none is sent; an empty string would be
	// passed on to the scheduler as an invalid crontab expression
	input := (*requests)[1].Variables["input"].(map[string]interface{})
	assert.Equal(t, map[string]interface{}{
		"includeExpiredCertificates": true,
		"includeRevokedCertificates": false,
	}, input["discoveryConfiguration"])
}

func TestUpdateCloudKeystoreFailsWhenNotFound(t *testing.T) {
	client, requests := newTestClient(t, keystoreListResponse(""))

	_, err := client.UpdateCloudKeystore(context.Background(), domain.UpdateCloudKeystoreRequest{ID: "k1", Name: strPtr("renamed")})
	require.ErrorIs(t, err, verror.CloudKeystoreNotFoundError)
	assert.Len(t, *requests, 1)
}

func TestListMachineIdentities(t *testing.T) {
	client, requests := newTestClient(t,
		`{"data":{"cloudMachineIdentities":{"nodes":[{"id":"m1","cloudKeystoreId":"k1","cloudKeystoreName":"acm","status":"DISCOVERED",
			"certificateId":"c1","metadata":{"__typename":"AWSCertificateMetadata","arn":"arn:aws:acm:cert"}}],
			"pageInfo":{"hasNextPage":false}}}}`,
	)

	identities, err := client.ListMachineIdentities(context.Background(), domain.ListCloudMachineIdentitiesRequest{KeystoreID: "k1"})
	require.NoError(t, err)
	require.Len(t, identities, 1)

	mi := identities[0]
	assert.Equal(t, "m1", mi.ID)
	assert.Equal(t, "acm", mi.CloudKeystoreName)
	assert.Equal(t, domain.MachineIdentityStatusDiscovered, mi.Status)
	require.NotNil(t, mi.Metadata)
	assert.Equal(t, domain.CloudKeystoreTypeACM, mi.Metadata.GetKeystoreType())
	assert.Equal(t, "arn:aws:acm:cert", mi.Metadata.GetValue("arn"))

	assert.Equal(t, "k1", (*requests)[0].Variables["cloudKeystoreId"])
	assert.NotContains(t, (*requests)[0].Variables, "newlyDiscovered")
}
