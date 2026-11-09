package cloud

import (
	"context"
	"fmt"
	"log"
	"strings"

	"github.com/google/uuid"

	"github.com/Venafi/vcert/v5/pkg/domain"
	"github.com/Venafi/vcert/v5/pkg/endpoint"
	"github.com/Venafi/vcert/v5/pkg/webclient/cloudproviders"
)

var (
	_ endpoint.CloudProviderManager = (*Connector)(nil)
	_ endpoint.CloudKeystoreManager = (*Connector)(nil)
)

// managementClient returns the GraphQL client used for cloud provider and
// keystore management, which is only available once the connector is authenticated
func (c *Connector) managementClient() (*cloudproviders.CloudProvidersClient, error) {
	if c.cloudProvidersClient == nil {
		return nil, fmt.Errorf("must be authenticated to manage cloud providers and keystores")
	}
	return c.cloudProvidersClient, nil
}

// resolveTeamID returns the ID of the given team, which may be given by ID or
// by name. Cloud providers and keystores must be owned by a team in CyberArk
// Certificate Manager, SaaS, and names are what users see in the UI.
func (c *Connector) resolveTeamID(team string) (string, error) {
	if _, err := uuid.Parse(team); err == nil {
		return team, nil
	}

	teams, err := c.retrieveTeams()
	if err != nil {
		return "", fmt.Errorf("failed to retrieve teams to look up team %q: %w", team, err)
	}
	for _, t := range teams.Teams {
		if strings.EqualFold(t.Name, team) {
			return t.ID, nil
		}
	}
	return "", fmt.Errorf("could not find team %q", team)
}

func (c *Connector) ListCloudProviders(filter domain.GetCloudProviderRequest) ([]domain.CloudProvider, error) {
	client, err := c.managementClient()
	if err != nil {
		return nil, err
	}
	return client.ListCloudProviders(context.Background(), filter)
}

// CreateCloudProvider creates a cloud provider. request.TeamID is required and
// may be a team ID or a team name.
func (c *Connector) CreateCloudProvider(request domain.CreateCloudProviderRequest) (*domain.CloudProvider, error) {
	log.Printf("creating cloud provider %s of type %s", request.Name, request.Type)
	client, err := c.managementClient()
	if err != nil {
		return nil, err
	}
	if request.TeamID == "" {
		return nil, fmt.Errorf("an owning team is required to create a cloud provider")
	}
	request.TeamID, err = c.resolveTeamID(request.TeamID)
	if err != nil {
		return nil, err
	}
	return client.CreateCloudProvider(context.Background(), request)
}

// UpdateCloudProvider updates a cloud provider. request.TeamID may be a team
// ID or a team name.
func (c *Connector) UpdateCloudProvider(request domain.UpdateCloudProviderRequest) (*domain.CloudProvider, error) {
	log.Printf("updating cloud provider with ID %s", request.ID)
	client, err := c.managementClient()
	if err != nil {
		return nil, err
	}
	if request.TeamID != nil {
		teamID, err := c.resolveTeamID(*request.TeamID)
		if err != nil {
			return nil, err
		}
		request.TeamID = &teamID
	}
	return client.UpdateCloudProvider(context.Background(), request)
}

func (c *Connector) DeleteCloudProvider(cloudProviderID string) error {
	log.Printf("deleting cloud provider with ID %s", cloudProviderID)
	client, err := c.managementClient()
	if err != nil {
		return err
	}
	return client.DeleteCloudProvider(context.Background(), cloudProviderID)
}

func (c *Connector) ValidateCloudProvider(cloudProviderID string) (*domain.CloudProviderValidationResult, error) {
	log.Printf("validating cloud provider with ID %s", cloudProviderID)
	client, err := c.managementClient()
	if err != nil {
		return nil, err
	}
	return client.ValidateCloudProvider(context.Background(), cloudProviderID)
}

func (c *Connector) ListCloudKeystores(filter domain.GetCloudKeystoreRequest) ([]domain.CloudKeystore, error) {
	client, err := c.managementClient()
	if err != nil {
		return nil, err
	}
	return client.ListCloudKeystores(context.Background(), filter)
}

// CreateCloudKeystore creates a cloud keystore. request.TeamID is required and
// may be a team ID or a team name.
func (c *Connector) CreateCloudKeystore(request domain.CreateCloudKeystoreRequest) (*domain.CloudKeystore, error) {
	log.Printf("creating cloud keystore %s of type %s for cloud provider with ID %s", request.Name, request.Type, request.CloudProviderID)
	client, err := c.managementClient()
	if err != nil {
		return nil, err
	}
	if request.TeamID == "" {
		return nil, fmt.Errorf("an owning team is required to create a cloud keystore")
	}
	request.TeamID, err = c.resolveTeamID(request.TeamID)
	if err != nil {
		return nil, err
	}
	return client.CreateCloudKeystore(context.Background(), request)
}

// UpdateCloudKeystore updates a cloud keystore. request.TeamID may be a team
// ID or a team name.
func (c *Connector) UpdateCloudKeystore(request domain.UpdateCloudKeystoreRequest) (*domain.CloudKeystore, error) {
	log.Printf("updating cloud keystore with ID %s", request.ID)
	client, err := c.managementClient()
	if err != nil {
		return nil, err
	}
	if request.TeamID != nil {
		teamID, err := c.resolveTeamID(*request.TeamID)
		if err != nil {
			return nil, err
		}
		request.TeamID = &teamID
	}
	return client.UpdateCloudKeystore(context.Background(), request)
}

func (c *Connector) DeleteCloudKeystore(cloudKeystoreID string) error {
	log.Printf("deleting cloud keystore with ID %s", cloudKeystoreID)
	client, err := c.managementClient()
	if err != nil {
		return err
	}
	return client.DeleteCloudKeystore(context.Background(), cloudKeystoreID)
}

func (c *Connector) StartCloudDiscovery(cloudKeystoreID string) (*domain.WorkflowResult, error) {
	// The API requires a websocket client ID to publish the workflow result to.
	// Progress is followed by polling the keystore instead, because a discovery
	// can outlive the websocket read, so nothing subscribes to this ID.
	wsClientID := uuid.New().String()
	log.Printf("starting discovery for cloud keystore with ID %s", cloudKeystoreID)
	client, err := c.managementClient()
	if err != nil {
		return nil, err
	}
	result, err := client.StartCloudDiscovery(context.Background(), cloudKeystoreID, wsClientID)
	if err != nil {
		return nil, err
	}
	log.Printf("discovery workflow %s started with ID %s", result.WorkflowName, result.WorkflowID)
	return result, nil
}

func (c *Connector) AbortCloudDiscovery(cloudKeystoreID string) error {
	log.Printf("aborting discovery for cloud keystore with ID %s", cloudKeystoreID)
	client, err := c.managementClient()
	if err != nil {
		return err
	}
	return client.AbortCloudDiscovery(context.Background(), cloudKeystoreID)
}

func (c *Connector) ListMachineIdentities(request domain.ListCloudMachineIdentitiesRequest) ([]domain.CloudMachineIdentity, error) {
	if request.KeystoreID == "" {
		return nil, fmt.Errorf("cloud keystore ID cannot be empty")
	}
	client, err := c.managementClient()
	if err != nil {
		return nil, err
	}
	return client.ListMachineIdentities(context.Background(), request)
}
