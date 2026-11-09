package ngts

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Venafi/vcert/v5/pkg/domain"
	"github.com/Venafi/vcert/v5/pkg/webclient/cloudproviders"
)

func TestCloudManagementRequiresAuthentication(t *testing.T) {
	c := &Connector{}

	if _, err := c.ListCloudProviders(domain.GetCloudProviderRequest{}); err == nil || !strings.Contains(err.Error(), "must be authenticated") {
		t.Fatalf("expected an authentication error, got %v", err)
	}
	if err := c.DeleteCloudKeystore("k1"); err == nil || !strings.Contains(err.Error(), "must be authenticated") {
		t.Fatalf("expected an authentication error, got %v", err)
	}
}

func TestStartCloudDiscoveryUsesTheGraphQLClient(t *testing.T) {
	var body string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		body = string(b)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":{"startCloudDiscovery":{"workflowId":"w1","workflowName":"discovery"}}}`))
	}))
	defer server.Close()

	c := &Connector{cloudProvidersClient: cloudproviders.NewCloudProvidersClient(server.URL, server.Client())}
	result, err := c.StartCloudDiscovery("k1")
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	if result.WorkflowID != "w1" {
		t.Fatalf("expected workflow w1, got %s", result.WorkflowID)
	}
	// a websocket client ID must be generated, since the API requires one
	if !strings.Contains(body, `"cloudKeystoreId":"k1"`) || !strings.Contains(body, `"wsClientId":"`) {
		t.Fatalf("unexpected request body: %s", body)
	}
}
