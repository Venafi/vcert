/*
 * Copyright Venafi, Inc. and CyberArk Software Ltd. ("CyberArk")
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package main

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/urfave/cli/v2"

	"github.com/Venafi/vcert/v5"
	"github.com/Venafi/vcert/v5/pkg/domain"
	"github.com/Venafi/vcert/v5/pkg/endpoint"
)

// Helpers shared by the cloudprovider and cloudkeystore commands

func runBeforeCloudManagementCommand(c *cli.Context) error {
	return runBeforeProvisionCommand(c)
}

// cloudCommandName returns the command name including its parent, for example
// "cloudprovider create". cli.Command.FullName is not populated for
// subcommands by the time their action runs.
func cloudCommandName(c *cli.Context) string {
	names := make([]string, 0, 2)
	for _, ctx := range c.Lineage() {
		// the root context's command is the app itself
		if ctx.Command == nil || ctx.Command.Name == "" || ctx.Command.Name == c.App.Name {
			continue
		}
		names = append([]string{ctx.Command.Name}, names...)
	}
	return strings.Join(names, " ")
}

// connectForCloudManagement builds an authenticated connector from the flags
func connectForCloudManagement(c *cli.Context) (endpoint.Connector, error) {
	err := setTLSConfig()
	if err != nil {
		return nil, err
	}
	cfg, err := buildConfig(c, &flags)
	if err != nil {
		return nil, fmt.Errorf("failed to build vcert config: %s", err)
	}
	connector, err := vcert.NewClient(&cfg)
	if err != nil {
		return nil, fmt.Errorf("unable to connect to %s: %s", cfg.ConnectorType, err)
	}
	logf("Successfully connected to %s", cfg.ConnectorType)
	return connector, nil
}

func getCloudProviderManager(c *cli.Context) (endpoint.CloudProviderManager, error) {
	connector, err := connectForCloudManagement(c)
	if err != nil {
		return nil, err
	}
	manager, ok := connector.(endpoint.CloudProviderManager)
	if !ok {
		return nil, fmt.Errorf("command %s not supported for %s", cloudCommandName(c), connector.GetType())
	}
	return manager, nil
}

func getCloudKeystoreManager(c *cli.Context) (endpoint.CloudKeystoreManager, error) {
	connector, err := connectForCloudManagement(c)
	if err != nil {
		return nil, err
	}
	manager, ok := connector.(endpoint.CloudKeystoreManager)
	if !ok {
		return nil, fmt.Errorf("command %s not supported for %s", cloudCommandName(c), connector.GetType())
	}
	return manager, nil
}

// resolveCloudProvider finds the single cloud provider matching the given ID
// and/or name. The API cannot filter by ID, so an ID-only lookup lists all
// providers.
func resolveCloudProvider(manager endpoint.CloudProviderManager, id string, name string) (*domain.CloudProvider, error) {
	providers, err := manager.ListCloudProviders(domain.GetCloudProviderRequest{Name: name})
	if err != nil {
		return nil, err
	}

	matches := make([]domain.CloudProvider, 0, 1)
	for _, p := range providers {
		if name != "" && p.Name != name {
			continue
		}
		if id != "" && p.ID != id {
			continue
		}
		matches = append(matches, p)
	}

	switch len(matches) {
	case 1:
		return &matches[0], nil
	case 0:
		return nil, fmt.Errorf("could not find cloud provider with %s", describeSelector("ID", id, "name", name))
	default:
		return nil, fmt.Errorf("found %d cloud providers with %s. Use --%s instead", len(matches), describeSelector("ID", id, "name", name), flagProviderID.Name)
	}
}

// resolveCloudKeystore finds the single cloud keystore matching the selector flags
func resolveCloudKeystore(manager endpoint.CloudKeystoreManager) (*domain.CloudKeystore, error) {
	filter := domain.GetCloudKeystoreRequest{
		CloudKeystoreID:   optionalFlag(flags.keystoreID),
		CloudKeystoreName: optionalFlag(flags.keystoreName),
		CloudProviderID:   optionalFlag(flags.providerID),
		CloudProviderName: optionalFlag(flags.providerName),
	}
	keystores, err := manager.ListCloudKeystores(filter)
	if err != nil {
		return nil, err
	}

	selector := describeSelector("ID", flags.keystoreID, "name", flags.keystoreName)
	switch len(keystores) {
	case 1:
		return &keystores[0], nil
	case 0:
		return nil, fmt.Errorf("could not find cloud keystore with %s", selector)
	default:
		return nil, fmt.Errorf("found %d cloud keystores with %s. Use --%s, or narrow it down with --%s or --%s",
			len(keystores), selector, flagCloudKeystoreID.Name, flagProviderID.Name, flagCloudProviderName.Name)
	}
}

func describeSelector(idLabel string, id string, nameLabel string, name string) string {
	parts := make([]string, 0, 2)
	if id != "" {
		parts = append(parts, fmt.Sprintf("%s %s", idLabel, id))
	}
	if name != "" {
		parts = append(parts, fmt.Sprintf("%s %q", nameLabel, name))
	}
	return strings.Join(parts, " and ")
}

func optionalFlag(value string) *string {
	if value == "" {
		return nil
	}
	return &value
}

// optionalBoolFlag returns a pointer to the flag value only when the user set
// it, so that unset flags leave the server-side value unchanged
func optionalBoolFlag(c *cli.Context, name string, value bool) *bool {
	if !c.IsSet(name) {
		return nil
	}
	return &value
}

func discoveryOptionsFromFlags(c *cli.Context) *domain.CloudDiscoveryOptions {
	options := &domain.CloudDiscoveryOptions{
		ScheduleSpecification:      optionalFlag(flags.discoverySchedule),
		IncludeExpiredCertificates: optionalBoolFlag(c, flagIncludeExpired.Name, flags.includeExpired),
		IncludeRevokedCertificates: optionalBoolFlag(c, flagIncludeRevoked.Name, flags.includeRevoked),
	}
	if options.ScheduleSpecification == nil && options.IncludeExpiredCertificates == nil && options.IncludeRevokedCertificates == nil {
		return nil
	}
	return options
}

// textWriter is implemented by the outputs of the cloud management commands
// to render themselves in the default text format
type textWriter interface {
	text() string
}

// writeCloudManagementResult prints the result as text or JSON, according to
// --format, to STDOUT or to the file given by --file
func writeCloudManagementResult(result textWriter) error {
	var out string
	if strings.ToLower(flags.provisionFormat) == formatJson {
		b, err := json.MarshalIndent(result, "", "    ")
		if err != nil {
			return fmt.Errorf("failed to construct JSON: %s", err)
		}
		out = string(b) + "\n"
	} else {
		out = result.text()
	}

	if flags.provisionOutputFile != "" {
		return os.WriteFile(flags.provisionOutputFile, []byte(out), 0600)
	}
	_, err := fmt.Fprint(os.Stdout, out)
	return err
}

type cloudProviderOutput struct {
	ID             string `json:"id"`
	Name           string `json:"name"`
	Type           string `json:"type"`
	Status         string `json:"status"`
	StatusDetails  string `json:"statusDetails,omitempty"`
	KeystoresCount int    `json:"keystoresCount"`
}

func newCloudProviderOutput(p domain.CloudProvider) cloudProviderOutput {
	return cloudProviderOutput{
		ID:             p.ID,
		Name:           p.Name,
		Type:           p.Type.String(),
		Status:         p.Status.String(),
		StatusDetails:  p.StatusDetails,
		KeystoresCount: p.KeystoresCount,
	}
}

func (o cloudProviderOutput) text() string {
	s := fmt.Sprintf("id: %s\nname: %s\ntype: %s\nstatus: %s\n", o.ID, o.Name, o.Type, o.Status)
	if o.StatusDetails != "" {
		s += fmt.Sprintf("statusDetails: %s\n", o.StatusDetails)
	}
	s += fmt.Sprintf("keystoresCount: %d\n", o.KeystoresCount)
	return s
}

type cloudProviderListOutput []cloudProviderOutput

func (o cloudProviderListOutput) text() string {
	items := make([]string, 0, len(o))
	for _, p := range o {
		items = append(items, p.text())
	}
	return strings.Join(items, "\n")
}

type cloudProviderValidationOutput struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Status  string `json:"status"`
	Details string `json:"details,omitempty"`
}

func (o cloudProviderValidationOutput) text() string {
	s := fmt.Sprintf("id: %s\nname: %s\nstatus: %s\n", o.ID, o.Name, o.Status)
	if o.Details != "" {
		s += fmt.Sprintf("details: %s\n", o.Details)
	}
	return s
}

type deletedOutput struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Deleted bool   `json:"deleted"`
}

func (o deletedOutput) text() string {
	return fmt.Sprintf("id: %s\nname: %s\ndeleted: %t\n", o.ID, o.Name, o.Deleted)
}

type cloudDiscoveryOutput struct {
	Status                   string     `json:"status"`
	StatusDetails            string     `json:"statusDetails,omitempty"`
	TotalCertificatesCount   int        `json:"totalCertificatesCount"`
	NewCertificatesCount     int        `json:"newCertificatesCount"`
	UpdatedCertificatesCount int        `json:"updatedCertificatesCount"`
	MissingCertificatesCount int        `json:"missingCertificatesCount"`
	StartTime                *time.Time `json:"startTime,omitempty"`
	EndTime                  *time.Time `json:"endTime,omitempty"`
}

func newCloudDiscoveryOutput(d *domain.CloudDiscovery) *cloudDiscoveryOutput {
	if d == nil {
		return nil
	}
	return &cloudDiscoveryOutput{
		Status:                   d.Status.String(),
		StatusDetails:            d.StatusDetails,
		TotalCertificatesCount:   d.TotalCertificatesCount,
		NewCertificatesCount:     d.NewCertificatesCount,
		UpdatedCertificatesCount: d.UpdatedCertificatesCount,
		MissingCertificatesCount: d.MissingCertificatesCount,
		StartTime:                d.StartTime,
		EndTime:                  d.EndTime,
	}
}

func (o *cloudDiscoveryOutput) text(prefix string) string {
	s := fmt.Sprintf("%sstatus: %s\n", prefix, o.Status)
	if o.StatusDetails != "" {
		s += fmt.Sprintf("%sstatusDetails: %s\n", prefix, o.StatusDetails)
	}
	s += fmt.Sprintf("%stotalCertificatesCount: %d\n", prefix, o.TotalCertificatesCount)
	s += fmt.Sprintf("%snewCertificatesCount: %d\n", prefix, o.NewCertificatesCount)
	s += fmt.Sprintf("%supdatedCertificatesCount: %d\n", prefix, o.UpdatedCertificatesCount)
	s += fmt.Sprintf("%smissingCertificatesCount: %d\n", prefix, o.MissingCertificatesCount)
	if o.StartTime != nil {
		s += fmt.Sprintf("%sstartTime: %s\n", prefix, o.StartTime.Format(time.RFC3339))
	}
	if o.EndTime != nil {
		s += fmt.Sprintf("%sendTime: %s\n", prefix, o.EndTime.Format(time.RFC3339))
	}
	return s
}

type cloudKeystoreOutput struct {
	ID                         string                `json:"id"`
	Name                       string                `json:"name"`
	Type                       string                `json:"type"`
	CloudProviderID            string                `json:"cloudProviderId,omitempty"`
	CloudProviderName          string                `json:"cloudProviderName,omitempty"`
	MachineIdentitiesCount     int                   `json:"machineIdentitiesCount"`
	AWSRegion                  string                `json:"awsRegion,omitempty"`
	AWSAccountID               string                `json:"awsAccountId,omitempty"`
	AzureKeyVaultName          string                `json:"azureKeyVaultName,omitempty"`
	GCPProjectID               string                `json:"gcpProjectId,omitempty"`
	GCPLocation                string                `json:"gcpLocation,omitempty"`
	DiscoverySchedule          string                `json:"discoverySchedule,omitempty"`
	IncludeExpiredCertificates *bool                 `json:"includeExpiredCertificates,omitempty"`
	IncludeRevokedCertificates *bool                 `json:"includeRevokedCertificates,omitempty"`
	Discovery                  *cloudDiscoveryOutput `json:"discovery,omitempty"`
}

func newCloudKeystoreOutput(k domain.CloudKeystore) cloudKeystoreOutput {
	o := cloudKeystoreOutput{
		ID:                     k.ID,
		Name:                   k.Name,
		Type:                   k.Type.String(),
		CloudProviderID:        k.CloudProviderID,
		CloudProviderName:      k.CloudProviderName,
		MachineIdentitiesCount: k.MachineIdentitiesCount,
		Discovery:              newCloudDiscoveryOutput(k.Discovery),
	}
	if k.ACM != nil {
		o.AWSRegion = k.ACM.Region
		o.AWSAccountID = k.ACM.AccountID
	}
	if k.AKV != nil {
		o.AzureKeyVaultName = k.AKV.KeyVaultName
	}
	if k.GCM != nil {
		o.GCPProjectID = k.GCM.ProjectID
		o.GCPLocation = k.GCM.Location
	}
	if k.DiscoveryConfiguration != nil {
		o.DiscoverySchedule = k.DiscoveryConfiguration.ScheduleSpecification
		o.IncludeExpiredCertificates = &k.DiscoveryConfiguration.IncludeExpiredCertificates
		o.IncludeRevokedCertificates = &k.DiscoveryConfiguration.IncludeRevokedCertificates
	}
	return o
}

func (o cloudKeystoreOutput) text() string {
	s := fmt.Sprintf("id: %s\nname: %s\ntype: %s\n", o.ID, o.Name, o.Type)
	if o.CloudProviderID != "" {
		s += fmt.Sprintf("cloudProviderId: %s\ncloudProviderName: %s\n", o.CloudProviderID, o.CloudProviderName)
	}
	s += fmt.Sprintf("machineIdentitiesCount: %d\n", o.MachineIdentitiesCount)
	for _, kv := range [][2]string{
		{"awsRegion", o.AWSRegion},
		{"awsAccountId", o.AWSAccountID},
		{"azureKeyVaultName", o.AzureKeyVaultName},
		{"gcpProjectId", o.GCPProjectID},
		{"gcpLocation", o.GCPLocation},
		{"discoverySchedule", o.DiscoverySchedule},
	} {
		if kv[1] != "" {
			s += fmt.Sprintf("%s: %s\n", kv[0], kv[1])
		}
	}
	if o.IncludeExpiredCertificates != nil {
		s += fmt.Sprintf("includeExpiredCertificates: %t\n", *o.IncludeExpiredCertificates)
	}
	if o.IncludeRevokedCertificates != nil {
		s += fmt.Sprintf("includeRevokedCertificates: %t\n", *o.IncludeRevokedCertificates)
	}
	if o.Discovery != nil {
		s += "discovery:\n" + o.Discovery.text("  ")
	}
	return s
}

type cloudKeystoreListOutput []cloudKeystoreOutput

func (o cloudKeystoreListOutput) text() string {
	items := make([]string, 0, len(o))
	for _, k := range o {
		items = append(items, k.text())
	}
	return strings.Join(items, "\n")
}

type discoveryStartedOutput struct {
	KeystoreID   string `json:"keystoreId"`
	KeystoreName string `json:"keystoreName"`
	WorkflowID   string `json:"workflowId"`
	WorkflowName string `json:"workflowName"`
}

func (o discoveryStartedOutput) text() string {
	return fmt.Sprintf("keystoreId: %s\nkeystoreName: %s\nworkflowId: %s\nworkflowName: %s\n", o.KeystoreID, o.KeystoreName, o.WorkflowID, o.WorkflowName)
}

type discoveryAbortedOutput struct {
	KeystoreID   string `json:"keystoreId"`
	KeystoreName string `json:"keystoreName"`
	Aborted      bool   `json:"aborted"`
}

func (o discoveryAbortedOutput) text() string {
	return fmt.Sprintf("keystoreId: %s\nkeystoreName: %s\naborted: %t\n", o.KeystoreID, o.KeystoreName, o.Aborted)
}

type machineIdentityOutput struct {
	ID            string                 `json:"id"`
	CertificateID string                 `json:"certificateId"`
	Status        string                 `json:"status"`
	StatusDetails string                 `json:"statusDetails,omitempty"`
	Metadata      map[string]interface{} `json:"metadata,omitempty"`
}

func newMachineIdentityOutput(mi domain.CloudMachineIdentity) machineIdentityOutput {
	o := machineIdentityOutput{
		ID:            mi.ID,
		CertificateID: mi.CertificateID,
		Status:        mi.Status.String(),
		StatusDetails: mi.StatusDetails,
	}
	if mi.Metadata != nil {
		o.Metadata = make(map[string]interface{})
		for k, v := range mi.Metadata.GetMetadata() {
			if k == "__typename" {
				continue
			}
			o.Metadata[k] = v
		}
	}
	return o
}

func (o machineIdentityOutput) text() string {
	s := fmt.Sprintf("id: %s\ncertificateId: %s\nstatus: %s\n", o.ID, o.CertificateID, o.Status)
	if o.StatusDetails != "" {
		s += fmt.Sprintf("statusDetails: %s\n", o.StatusDetails)
	}
	keys := make([]string, 0, len(o.Metadata))
	for k := range o.Metadata {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		s += fmt.Sprintf("%s: %v\n", k, o.Metadata[k])
	}
	return s
}

type machineIdentityListOutput []machineIdentityOutput

func (o machineIdentityListOutput) text() string {
	items := make([]string, 0, len(o))
	for _, mi := range o {
		items = append(items, mi.text())
	}
	return strings.Join(items, "\n")
}
