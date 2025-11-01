package cloud

import (
	"fmt"
	"log"
	"net/http"

	"github.com/Venafi/vcert/v5/pkg/policy"
)

func (c *Connector) GetPolicy(name string) (*policy.PolicySpecification, error) {
	if !c.isAuthenticated() {
		return nil, fmt.Errorf("must be autheticated to request a certificate")
	}

	cit, err := retrievePolicySpecification(c, name)
	if err != nil {
		return nil, err
	}

	info, err := getCertificateAuthorityInfoFromCloud(cit.CertificateAuthority, cit.CertificateAuthorityAccountId, cit.CertificateAuthorityProductOptionId, c)

	if err != nil {
		return nil, err
	}

	log.Println("Building policy")
	ps := buildPolicySpecification(cit, info, true)

	// getting the users to set to the PolicySpecification
	policyUsers, err := c.getUsers()
	if err != nil {
		return nil, err
	}
	ps.Users = policyUsers

	return ps, nil
}

func (c *Connector) SetPolicy(name string, ps *policy.PolicySpecification) (string, error) {
	if !c.isAuthenticated() {
		return "", fmt.Errorf("must be autheticated to request a certificate")
	}

	err := policy.ValidateCloudPolicySpecification(ps)
	if err != nil {
		return "", err
	}

	log.Printf("policy specification is valid")

	var status string

	//validate if zone name is set and if zone already exist on CyberArk Certificate Manager, SaaS if not create it.
	citName := policy.GetCitName(name)

	if citName == "" {
		return "", fmt.Errorf("cit name is empty, please provide zone in the format: app_name\\cit_name")
	}

	//get certificate authority product option io
	var caDetails *policy.CADetails

	if ps.Policy != nil && ps.Policy.CertificateAuthority != nil && *(ps.Policy.CertificateAuthority) != "" {
		caDetails, err = getCertificateAuthorityDetails(*(ps.Policy.CertificateAuthority), c)

		if err != nil {
			return "", err
		}

	} else {
		if ps.Policy != nil {

			defaultCA := policy.DefaultCA
			ps.Policy.CertificateAuthority = &defaultCA

			caDetails, err = getCertificateAuthorityDetails(*(ps.Policy.CertificateAuthority), c)
			if err != nil {
				return "", err
			}

		} else {
			//policy is not specified so we get the default CA
			caDetails, err = getCertificateAuthorityDetails(policy.DefaultCA, c)
			if err != nil {
				return "", err
			}
		}
	}

	//at this moment we know that ps.Policy.CertificateAuthority is valid.

	req, err := policy.BuildCloudCitRequest(ps, caDetails)
	if err != nil {
		return "", err
	}
	req.Name = citName

	url := c.getURL(urlIssuingTemplate)

	cit, err := getCit(c, citName)

	if err != nil {
		return "", err
	}

	if cit != nil {
		log.Printf("updating issuing template: %s", citName)
		//update cit using the new values
		url = fmt.Sprint(url, "/", cit.ID)
		statusCode, status, body, err := c.request("PUT", url, req)

		if err != nil {
			return "", err
		}

		cit, err = parseCitResult(http.StatusOK, statusCode, status, body)

		if err != nil {
			return status, err
		}

	} else {
		log.Printf("creating issuing template: %s", citName)
		//var body []byte
		statusCode, status, body, err := c.request("POST", url, req)

		if err != nil {
			return "", err
		}

		cit, err = parseCitResult(http.StatusCreated, statusCode, status, body)

		if err != nil {
			return status, err
		}

	}

	//validate if appName is set and if app already exist on CyberArk Certificate Manager, SaaS if not create it
	//and as final steps link the app with the cit.
	appName := policy.GetApplicationName(name)

	if appName == "" {
		return "", fmt.Errorf("application name is empty, please provide zone in the format: app_name\\cit_name")
	}

	appDetails, statusCode, err := c.getAppDetailsByName(appName)

	if err != nil && statusCode == 404 { //means application was not found.
		log.Printf("creating application: %s", appName)

		_, err = c.createApplication(appName, ps, cit)
		if err != nil {
			return "", err
		}

	} else { //determine if the application needs to be updated
		log.Printf("updating application: %s", appName)
		err = c.updateApplication(name, ps, cit, appDetails)
		if err != nil {
			return "", err
		}
	}

	log.Printf("policy successfully applied to %s", name)

	return status, nil
}

func (c *Connector) GetPolicyWithRegex(name string) (*policy.PolicySpecification, error) {

	cit, err := retrievePolicySpecification(c, name)

	if err != nil {
		return nil, err
	}

	info, err := getCertificateAuthorityInfoFromCloud(cit.CertificateAuthority, cit.CertificateAuthorityAccountId, cit.CertificateAuthorityProductOptionId, c)

	if err != nil {
		return nil, err
	}

	log.Println("Building policy")
	ps := buildPolicySpecification(cit, info, false)

	return ps, nil
}

func retrievePolicySpecification(c *Connector, name string) (*certificateTemplate, error) {
	appName := policy.GetApplicationName(name)
	if appName != "" {
		c.zone.appName = appName
	} else {
		return nil, fmt.Errorf("application name is not valid, please provide a valid zone name in the format: appName\\CitName")
	}
	citName := policy.GetCitName(name)
	if citName != "" {
		c.zone.templateAlias = citName
	} else {
		return nil, fmt.Errorf("cit name is not valid, please provide a valid zone name in the format: appName\\CitName")
	}

	log.Println("Getting CIT")
	cit, err := c.getTemplateByID()

	if err != nil {
		return nil, err
	}

	return cit, nil

}

func (c *Connector) getUsers() ([]string, error) {
	var usersList []string
	appDetails, _, err := c.getAppDetailsByName(c.zone.getApplicationName())
	if err != nil {
		return nil, err
	}
	var teamsList *teams
	for _, owner := range appDetails.OwnerIdType {
		if owner.OwnerType == UserType.String() {
			retrievedUser, userErr := c.retrieveUser(owner.OwnerId)
			if userErr != nil {
				return nil, userErr
			}
			usersList = append(usersList, retrievedUser.Username)
		} else if owner.OwnerType == TeamType.String() {
			if teamsList == nil {
				teamsList, err = c.retrieveTeams()
				if err != nil {
					return nil, err
				}
			}
			if teamsList != nil {
				for _, t := range teamsList.Teams {
					if t.ID == owner.OwnerId {
						usersList = append(usersList, t.Name)
						break
					}
				}
			}
		}

	}
	return usersList, nil
}

func PolicyExist(policyName string, c *Connector) (bool, error) {
	c.zone.appName = policy.GetApplicationName(policyName)
	citName := policy.GetCitName(policyName)
	if citName != "" {
		c.zone.templateAlias = citName
	} else {
		return false, fmt.Errorf("cit name is not valid, please provide a valid zone name in the format: appName\\CitName")
	}

	_, err := c.getTemplateByID()
	return err == nil, nil
}

func (c *Connector) createApplication(appName string, ps *policy.PolicySpecification, cit *certificateTemplate) (*policy.Application, error) {
	appIssuingTemplate := make(map[string]string)
	appIssuingTemplate[cit.Name] = cit.ID

	var owners []policy.OwnerIdType
	var err error
	var statusCode int
	var status string

	//if users are passed to the PS, resolve the related Owners to set them
	if len(ps.Users) > 0 {
		owners, err = c.resolveOwners(ps.Users)
	} else { //if users are not specified in PS, then the current User should be used as owner
		var owner *policy.OwnerIdType
		owner, err = c.getOwnerFromUserDetails()
		if owner != nil {
			owners = []policy.OwnerIdType{*owner}
		}
	}

	if err != nil {
		return nil, fmt.Errorf("an error happened trying to resolve the owners: %w", err)
	}

	//create application
	appReq := policy.Application{
		OwnerIdsAndTypes:                     owners,
		Name:                                 appName,
		CertificateIssuingTemplateAliasIdMap: appIssuingTemplate,
	}

	url := c.getURL(urlAppRoot)

	statusCode, status, _, err = c.request("POST", url, appReq)
	if err != nil {
		return nil, err
	}
	if statusCode != 201 {
		return nil, fmt.Errorf("unexpected result %s attempting to create application %s", status, appName)
	}

	return &appReq, nil
}

func (c *Connector) updateApplication(name string, ps *policy.PolicySpecification, cit *certificateTemplate, appDetails *ApplicationDetails) error {

	//creating the app to use as request
	appReq := createAppUpdateRequest(appDetails)

	//determining if the relationship between application and cit exist
	citAddedToApp := false
	exist, err := PolicyExist(name, c)
	if err != nil {
		return err
	}
	if !exist {
		c.addCitToApp(&appReq, cit)
		citAddedToApp = true
	}

	//determining if the owners where provided and should be updated
	ownersUpdated := false
	//given that the application exists, the only way to update the owners at the application
	//is that users in the policy specification were provided
	if len(ps.Users) > 0 {
		//resolving and setting owners
		owners, err := c.resolveOwners(ps.Users)
		if err != nil {
			return fmt.Errorf("an error happened trying to resolve the owners: %w", err)
		}
		appReq.OwnerIdsAndTypes = owners
		ownersUpdated = true
	}

	//if the cit was added to the app or the owners were updated, then is required
	//to update the application
	if citAddedToApp || ownersUpdated {
		url := c.getURL(urlAppRoot)
		url = fmt.Sprint(url, "/", appDetails.ApplicationId)
		_, _, _, err = c.request("PUT", url, appReq)
		if err != nil {
			return err
		}
	}

	return nil
}

func (c *Connector) addCitToApp(app *policy.Application, cit *certificateTemplate) {
	//add cit to the map.
	value, ok := app.CertificateIssuingTemplateAliasIdMap[cit.Name]
	if !ok || value != cit.ID {
		app.CertificateIssuingTemplateAliasIdMap[cit.Name] = cit.ID
	}
}

func (c *Connector) resolveOwners(usersList []string) ([]policy.OwnerIdType, error) {

	var owners []policy.OwnerIdType
	var teams *teams
	var err error

	for _, userName := range usersList {
		//The error should be ignored in order to confirm if the userName is not a TeamName
		users, _ := c.retrieveUsers(userName)

		if users != nil {
			owners = appendOwner(owners, users.Users[0].ID, UserType)
		} else {
			if teams == nil {
				teams, err = c.retrieveTeams()
			}
			if err != nil {
				return nil, err
			}
			if teams != nil {
				var found = false
				for _, team := range teams.Teams {
					if team.Name == userName {
						owners = appendOwner(owners, team.ID, TeamType)
						found = true
						break
					}
				}
				if !found {
					return nil, fmt.Errorf("it was not possible to find the user %s", userName)
				}
			}
		}
	}

	return owners, err
}

func appendOwner(owners []policy.OwnerIdType, ownerId string, ownerType OwnerType) []policy.OwnerIdType {
	owner := createOwner(ownerId, ownerType)
	return append(owners, *owner)
}

func (c *Connector) getOwnerFromUserDetails() (*policy.OwnerIdType, error) {
	userDetails, err := c.getUserDetails()
	if err != nil {
		return nil, err
	}
	owner := createOwner(userDetails.User.ID, UserType)
	return owner, nil
}

func createOwner(ownerId string, ownerType OwnerType) *policy.OwnerIdType {
	ownerIdType := policy.OwnerIdType{
		OwnerId:   ownerId,
		OwnerType: ownerType.String(),
	}

	return &ownerIdType
}
