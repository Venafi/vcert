package ngts

import (
	"fmt"
	"log"
	"net/http"

	"github.com/Venafi/vcert/v5/pkg/policy"
)

func (c *Connector) GetPolicy(name string) (*policy.PolicySpecification, error) {
	if !c.isAuthenticated() {
		return nil, fmt.Errorf("must be authenticated to request a certificate")
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

	return ps, nil
}

func (c *Connector) SetPolicy(name string, ps *policy.PolicySpecification) (string, error) {
	if !c.isAuthenticated() {
		return "", fmt.Errorf("must be authenticated to request a certificate")
	}

	err := policy.ValidateCloudPolicySpecification(ps)
	if err != nil {
		return "", err
	}

	log.Printf("policy specification is valid")

	var status string

	//validate if zone name is set and if zone already exist on Palo Alto Networks Next-Gen Trust Security (NGTS) if not create it.
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

	// validate if appName is set and if app already exist on Palo Alto Networks Next-Gen Trust Security (NGTS)
	// link the app with the cit.
	appName := policy.GetApplicationName(name)
	if appName == "" {
		return "", fmt.Errorf("application name is empty, please provide zone in the format: app_name\\cit_name")
	}

	appDetails, statusCode, err := c.getAppDetailsByName(appName)
	if err != nil {
		return "", fmt.Errorf("unable to get application details by app name. Status code: %d, %w", statusCode, err)
	}

	log.Printf("updating application: %s", appName)
	err = c.updateApplication(name, ps, cit, appDetails)
	if err != nil {
		return "", err
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

	//if the cit was added to the app or the owners were updated, then is required
	//to update the application
	if citAddedToApp {
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
