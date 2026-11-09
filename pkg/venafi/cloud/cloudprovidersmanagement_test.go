package cloud

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Venafi/vcert/v5/pkg/domain"
	"github.com/Venafi/vcert/v5/pkg/webclient/cloudproviders"
)

const testTeamID = "a7b6e4a0-0c3e-11ee-9e8a-4b0a3c2d1e0f"

// newManagementTestConnector returns a connector whose REST and GraphQL
// requests go to a test server. graphqlResponses maps GraphQL operation names
// to their responses, and the bodies of the GraphQL requests are appended to
// graphqlRequests.
func newManagementTestConnector(t *testing.T, graphqlResponses map[string]string, graphqlRequests *[]string) *Connector {
	t.Helper()
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.HasSuffix(r.URL.Path, "/v1/teams"):
			_, _ = w.Write([]byte(`{"teams":[{"id":"` + testTeamID + `","name":"Cloud Admins"},{"id":"other","name":"Other"}]}`))
		case strings.HasSuffix(r.URL.Path, "/graphql"):
			body, _ := io.ReadAll(r.Body)
			*graphqlRequests = append(*graphqlRequests, string(body))
			var req struct {
				OperationName string `json:"operationName"`
			}
			_ = json.Unmarshal(body, &req)
			response, ok := graphqlResponses[req.OperationName]
			if !ok {
				t.Errorf("unexpected GraphQL operation %s", req.OperationName)
			}
			_, _ = w.Write([]byte(response))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)

	c, err := NewConnector(server.URL, "", false, nil)
	if err != nil {
		t.Fatal(err)
	}
	c.SetHTTPClient(server.Client())
	c.accessToken = "a-token"
	c.cloudProvidersClient = cloudproviders.NewCloudProvidersClient(c.getURL(urlGraphql), server.Client())
	return c
}

func TestCloudManagementRequiresAuthentication(t *testing.T) {
	c := &Connector{}

	if _, err := c.ListCloudKeystores(domain.GetCloudKeystoreRequest{}); err == nil || !strings.Contains(err.Error(), "must be authenticated") {
		t.Fatalf("expected an authentication error, got %v", err)
	}
}

func TestCreateCloudProviderResolvesTeamName(t *testing.T) {
	requests := make([]string, 0)
	c := newManagementTestConnector(t, map[string]string{
		"CreateCloudProvider": `{"data":{"createCloudProvider":{"id":"p1","name":"aws","type":"AWS","status":"NOT_VALIDATED","keystoresCount":0}}}`,
	}, &requests)

	_, err := c.CreateCloudProvider(domain.CreateCloudProviderRequest{
		Name:   "aws",
		Type:   domain.CloudProviderTypeAWS,
		TeamID: "cloud admins",
		AWS:    &domain.CloudProviderAWSConfiguration{AccountID: "123456789012", Role: "role"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	if len(requests) != 1 || !strings.Contains(requests[0], `"teamId":"`+testTeamID+`"`) {
		t.Fatalf("expected the team name to be sent as its ID, got %v", requests)
	}
}

func TestCreateCloudKeystoreRequiresTeam(t *testing.T) {
	requests := make([]string, 0)
	c := newManagementTestConnector(t, nil, &requests)

	_, err := c.CreateCloudKeystore(domain.CreateCloudKeystoreRequest{
		Name:            "acm",
		Type:            domain.CloudKeystoreTypeACM,
		CloudProviderID: "p1",
		ACM:             &domain.CloudKeystoreACMConfiguration{Region: "us-east-1"},
	})
	if err == nil || !strings.Contains(err.Error(), "owning team is required") {
		t.Fatalf("expected a team required error, got %v", err)
	}
	if len(requests) != 0 {
		t.Fatalf("expected no GraphQL request, got %v", requests)
	}
}

func TestResolveTeamID(t *testing.T) {
	requests := make([]string, 0)
	c := newManagementTestConnector(t, nil, &requests)

	id, err := c.resolveTeamID(testTeamID)
	if err != nil || id != testTeamID {
		t.Fatalf("expected an ID to be returned unchanged, got %q, %v", id, err)
	}

	if _, err := c.resolveTeamID("Missing Team"); err == nil || !strings.Contains(err.Error(), `could not find team "Missing Team"`) {
		t.Fatalf("expected a team not found error, got %v", err)
	}
}

func TestUpdateCloudKeystoreResolvesTeamName(t *testing.T) {
	requests := make([]string, 0)
	keystore := `{"id":"k1","name":"acm","type":"ACM","machineIdentitiesCount":0,
		"configuration":{"__typename":"CloudKeystoreACMConfiguration","region":"us-east-1"},
		"discoveryConfiguration":{"includeExpiredCertificates":false,"includeRevokedCertificates":false}}`
	c := newManagementTestConnector(t, map[string]string{
		"ListCloudKeystores":  `{"data":{"cloudKeystores":{"nodes":[` + keystore + `],"pageInfo":{"hasNextPage":false}}}}`,
		"UpdateCloudKeystore": `{"data":{"updateCloudKeystore":` + keystore + `}}`,
	}, &requests)

	team := "Cloud Admins"
	_, err := c.UpdateCloudKeystore(domain.UpdateCloudKeystoreRequest{ID: "k1", TeamID: &team})
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	// the keystore is read first so that its discovery settings can be kept
	if len(requests) != 2 || !strings.Contains(requests[1], `"teamId":"`+testTeamID+`"`) {
		t.Fatalf("expected the team name to be sent as its ID, got %v", requests)
	}
}
