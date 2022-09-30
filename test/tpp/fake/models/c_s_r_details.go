// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
)

// CSRDetails c s r details
//
// swagger:model CSRDetails
type CSRDetails struct {

	// city
	City *CompliantValue `json:"City,omitempty"`

	// common name
	CommonName *CompliantValue `json:"CommonName,omitempty"`

	// country
	Country *CompliantValue `json:"Country,omitempty"`

	// elliptic curve
	EllipticCurve *CompliantValue `json:"EllipticCurve,omitempty"`

	// key algorithm
	KeyAlgorithm *CompliantValue `json:"KeyAlgorithm,omitempty"`

	// key size
	KeySize *CompliantIntValue `json:"KeySize,omitempty"`

	// organization
	Organization *CompliantValue `json:"Organization,omitempty"`

	// organizational unit
	OrganizationalUnit *CompliantListValues `json:"OrganizationalUnit,omitempty"`

	// private key reused
	PrivateKeyReused *CompliantBoolValue `json:"PrivateKeyReused,omitempty"`

	// state
	State *CompliantValue `json:"State,omitempty"`

	// subj alt name Dns
	SubjAltNameDNS *CompliantListValues `json:"SubjAltNameDns,omitempty"`

	// subj alt name email
	SubjAltNameEmail *CompliantListValues `json:"SubjAltNameEmail,omitempty"`

	// subj alt name Ip
	SubjAltNameIP *CompliantListValues `json:"SubjAltNameIp,omitempty"`

	// subj alt name upn
	SubjAltNameUpn *CompliantListValues `json:"SubjAltNameUpn,omitempty"`

	// subj alt name Uri
	SubjAltNameURI *CompliantListValues `json:"SubjAltNameUri,omitempty"`
}

// Validate validates this c s r details
func (m *CSRDetails) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateCity(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateCommonName(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateCountry(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateEllipticCurve(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateKeyAlgorithm(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateKeySize(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateOrganization(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateOrganizationalUnit(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validatePrivateKeyReused(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateState(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateSubjAltNameDNS(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateSubjAltNameEmail(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateSubjAltNameIP(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateSubjAltNameUpn(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateSubjAltNameURI(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *CSRDetails) validateCity(formats strfmt.Registry) error {
	if swag.IsZero(m.City) { // not required
		return nil
	}

	if m.City != nil {
		if err := m.City.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("City")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("City")
			}
			return err
		}
	}

	return nil
}

func (m *CSRDetails) validateCommonName(formats strfmt.Registry) error {
	if swag.IsZero(m.CommonName) { // not required
		return nil
	}

	if m.CommonName != nil {
		if err := m.CommonName.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("CommonName")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("CommonName")
			}
			return err
		}
	}

	return nil
}

func (m *CSRDetails) validateCountry(formats strfmt.Registry) error {
	if swag.IsZero(m.Country) { // not required
		return nil
	}

	if m.Country != nil {
		if err := m.Country.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("Country")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("Country")
			}
			return err
		}
	}

	return nil
}

func (m *CSRDetails) validateEllipticCurve(formats strfmt.Registry) error {
	if swag.IsZero(m.EllipticCurve) { // not required
		return nil
	}

	if m.EllipticCurve != nil {
		if err := m.EllipticCurve.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("EllipticCurve")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("EllipticCurve")
			}
			return err
		}
	}

	return nil
}

func (m *CSRDetails) validateKeyAlgorithm(formats strfmt.Registry) error {
	if swag.IsZero(m.KeyAlgorithm) { // not required
		return nil
	}

	if m.KeyAlgorithm != nil {
		if err := m.KeyAlgorithm.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("KeyAlgorithm")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("KeyAlgorithm")
			}
			return err
		}
	}

	return nil
}

func (m *CSRDetails) validateKeySize(formats strfmt.Registry) error {
	if swag.IsZero(m.KeySize) { // not required
		return nil
	}

	if m.KeySize != nil {
		if err := m.KeySize.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("KeySize")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("KeySize")
			}
			return err
		}
	}

	return nil
}

func (m *CSRDetails) validateOrganization(formats strfmt.Registry) error {
	if swag.IsZero(m.Organization) { // not required
		return nil
	}

	if m.Organization != nil {
		if err := m.Organization.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("Organization")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("Organization")
			}
			return err
		}
	}

	return nil
}

func (m *CSRDetails) validateOrganizationalUnit(formats strfmt.Registry) error {
	if swag.IsZero(m.OrganizationalUnit) { // not required
		return nil
	}

	if m.OrganizationalUnit != nil {
		if err := m.OrganizationalUnit.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("OrganizationalUnit")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("OrganizationalUnit")
			}
			return err
		}
	}

	return nil
}

func (m *CSRDetails) validatePrivateKeyReused(formats strfmt.Registry) error {
	if swag.IsZero(m.PrivateKeyReused) { // not required
		return nil
	}

	if m.PrivateKeyReused != nil {
		if err := m.PrivateKeyReused.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("PrivateKeyReused")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("PrivateKeyReused")
			}
			return err
		}
	}

	return nil
}

func (m *CSRDetails) validateState(formats strfmt.Registry) error {
	if swag.IsZero(m.State) { // not required
		return nil
	}

	if m.State != nil {
		if err := m.State.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("State")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("State")
			}
			return err
		}
	}

	return nil
}

func (m *CSRDetails) validateSubjAltNameDNS(formats strfmt.Registry) error {
	if swag.IsZero(m.SubjAltNameDNS) { // not required
		return nil
	}

	if m.SubjAltNameDNS != nil {
		if err := m.SubjAltNameDNS.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("SubjAltNameDns")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("SubjAltNameDns")
			}
			return err
		}
	}

	return nil
}

func (m *CSRDetails) validateSubjAltNameEmail(formats strfmt.Registry) error {
	if swag.IsZero(m.SubjAltNameEmail) { // not required
		return nil
	}

	if m.SubjAltNameEmail != nil {
		if err := m.SubjAltNameEmail.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("SubjAltNameEmail")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("SubjAltNameEmail")
			}
			return err
		}
	}

	return nil
}

func (m *CSRDetails) validateSubjAltNameIP(formats strfmt.Registry) error {
	if swag.IsZero(m.SubjAltNameIP) { // not required
		return nil
	}

	if m.SubjAltNameIP != nil {
		if err := m.SubjAltNameIP.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("SubjAltNameIp")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("SubjAltNameIp")
			}
			return err
		}
	}

	return nil
}

func (m *CSRDetails) validateSubjAltNameUpn(formats strfmt.Registry) error {
	if swag.IsZero(m.SubjAltNameUpn) { // not required
		return nil
	}

	if m.SubjAltNameUpn != nil {
		if err := m.SubjAltNameUpn.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("SubjAltNameUpn")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("SubjAltNameUpn")
			}
			return err
		}
	}

	return nil
}

func (m *CSRDetails) validateSubjAltNameURI(formats strfmt.Registry) error {
	if swag.IsZero(m.SubjAltNameURI) { // not required
		return nil
	}

	if m.SubjAltNameURI != nil {
		if err := m.SubjAltNameURI.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("SubjAltNameUri")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("SubjAltNameUri")
			}
			return err
		}
	}

	return nil
}

// ContextValidate validate this c s r details based on the context it is used
func (m *CSRDetails) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateCity(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateCommonName(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateCountry(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateEllipticCurve(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateKeyAlgorithm(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateKeySize(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateOrganization(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateOrganizationalUnit(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidatePrivateKeyReused(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateState(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateSubjAltNameDNS(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateSubjAltNameEmail(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateSubjAltNameIP(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateSubjAltNameUpn(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateSubjAltNameURI(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *CSRDetails) contextValidateCity(ctx context.Context, formats strfmt.Registry) error {

	if m.City != nil {
		if err := m.City.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("City")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("City")
			}
			return err
		}
	}

	return nil
}

func (m *CSRDetails) contextValidateCommonName(ctx context.Context, formats strfmt.Registry) error {

	if m.CommonName != nil {
		if err := m.CommonName.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("CommonName")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("CommonName")
			}
			return err
		}
	}

	return nil
}

func (m *CSRDetails) contextValidateCountry(ctx context.Context, formats strfmt.Registry) error {

	if m.Country != nil {
		if err := m.Country.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("Country")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("Country")
			}
			return err
		}
	}

	return nil
}

func (m *CSRDetails) contextValidateEllipticCurve(ctx context.Context, formats strfmt.Registry) error {

	if m.EllipticCurve != nil {
		if err := m.EllipticCurve.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("EllipticCurve")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("EllipticCurve")
			}
			return err
		}
	}

	return nil
}

func (m *CSRDetails) contextValidateKeyAlgorithm(ctx context.Context, formats strfmt.Registry) error {

	if m.KeyAlgorithm != nil {
		if err := m.KeyAlgorithm.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("KeyAlgorithm")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("KeyAlgorithm")
			}
			return err
		}
	}

	return nil
}

func (m *CSRDetails) contextValidateKeySize(ctx context.Context, formats strfmt.Registry) error {

	if m.KeySize != nil {
		if err := m.KeySize.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("KeySize")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("KeySize")
			}
			return err
		}
	}

	return nil
}

func (m *CSRDetails) contextValidateOrganization(ctx context.Context, formats strfmt.Registry) error {

	if m.Organization != nil {
		if err := m.Organization.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("Organization")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("Organization")
			}
			return err
		}
	}

	return nil
}

func (m *CSRDetails) contextValidateOrganizationalUnit(ctx context.Context, formats strfmt.Registry) error {

	if m.OrganizationalUnit != nil {
		if err := m.OrganizationalUnit.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("OrganizationalUnit")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("OrganizationalUnit")
			}
			return err
		}
	}

	return nil
}

func (m *CSRDetails) contextValidatePrivateKeyReused(ctx context.Context, formats strfmt.Registry) error {

	if m.PrivateKeyReused != nil {
		if err := m.PrivateKeyReused.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("PrivateKeyReused")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("PrivateKeyReused")
			}
			return err
		}
	}

	return nil
}

func (m *CSRDetails) contextValidateState(ctx context.Context, formats strfmt.Registry) error {

	if m.State != nil {
		if err := m.State.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("State")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("State")
			}
			return err
		}
	}

	return nil
}

func (m *CSRDetails) contextValidateSubjAltNameDNS(ctx context.Context, formats strfmt.Registry) error {

	if m.SubjAltNameDNS != nil {
		if err := m.SubjAltNameDNS.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("SubjAltNameDns")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("SubjAltNameDns")
			}
			return err
		}
	}

	return nil
}

func (m *CSRDetails) contextValidateSubjAltNameEmail(ctx context.Context, formats strfmt.Registry) error {

	if m.SubjAltNameEmail != nil {
		if err := m.SubjAltNameEmail.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("SubjAltNameEmail")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("SubjAltNameEmail")
			}
			return err
		}
	}

	return nil
}

func (m *CSRDetails) contextValidateSubjAltNameIP(ctx context.Context, formats strfmt.Registry) error {

	if m.SubjAltNameIP != nil {
		if err := m.SubjAltNameIP.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("SubjAltNameIp")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("SubjAltNameIp")
			}
			return err
		}
	}

	return nil
}

func (m *CSRDetails) contextValidateSubjAltNameUpn(ctx context.Context, formats strfmt.Registry) error {

	if m.SubjAltNameUpn != nil {
		if err := m.SubjAltNameUpn.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("SubjAltNameUpn")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("SubjAltNameUpn")
			}
			return err
		}
	}

	return nil
}

func (m *CSRDetails) contextValidateSubjAltNameURI(ctx context.Context, formats strfmt.Registry) error {

	if m.SubjAltNameURI != nil {
		if err := m.SubjAltNameURI.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("SubjAltNameUri")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("SubjAltNameUri")
			}
			return err
		}
	}

	return nil
}

// MarshalBinary interface implementation
func (m *CSRDetails) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *CSRDetails) UnmarshalBinary(b []byte) error {
	var res CSRDetails
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}