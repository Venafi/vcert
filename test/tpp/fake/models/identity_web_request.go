// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"
	"strconv"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
)

// IdentityWebRequest identity web request
//
// swagger:model IdentityWebRequest
type IdentityWebRequest struct {

	// attribute name
	AttributeName string `json:"AttributeName,omitempty"`

	// container
	Container *IdentityEntry `json:"Container,omitempty"`

	// filter
	Filter string `json:"Filter,omitempty"`

	// group
	Group *IdentityEntry `json:"Group,omitempty"`

	// ID
	ID *IdentityEntry `json:"ID,omitempty"`

	// identity type
	IdentityType int64 `json:"IdentityType,omitempty"`

	// limit
	Limit int32 `json:"Limit,omitempty"`

	// members
	Members []*IdentityEntry `json:"Members"`

	// name
	Name *IdentityEntry `json:"Name,omitempty"`

	// new group name
	NewGroupName string `json:"NewGroupName,omitempty"`

	// old password
	OldPassword string `json:"OldPassword,omitempty"`

	// password
	Password string `json:"Password,omitempty"`

	// resolve nested
	ResolveNested int64 `json:"ResolveNested,omitempty"`

	// show members
	ShowMembers bool `json:"ShowMembers,omitempty"`
}

// Validate validates this identity web request
func (m *IdentityWebRequest) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateContainer(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateGroup(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateID(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateMembers(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateName(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *IdentityWebRequest) validateContainer(formats strfmt.Registry) error {
	if swag.IsZero(m.Container) { // not required
		return nil
	}

	if m.Container != nil {
		if err := m.Container.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("Container")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("Container")
			}
			return err
		}
	}

	return nil
}

func (m *IdentityWebRequest) validateGroup(formats strfmt.Registry) error {
	if swag.IsZero(m.Group) { // not required
		return nil
	}

	if m.Group != nil {
		if err := m.Group.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("Group")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("Group")
			}
			return err
		}
	}

	return nil
}

func (m *IdentityWebRequest) validateID(formats strfmt.Registry) error {
	if swag.IsZero(m.ID) { // not required
		return nil
	}

	if m.ID != nil {
		if err := m.ID.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("ID")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("ID")
			}
			return err
		}
	}

	return nil
}

func (m *IdentityWebRequest) validateMembers(formats strfmt.Registry) error {
	if swag.IsZero(m.Members) { // not required
		return nil
	}

	for i := 0; i < len(m.Members); i++ {
		if swag.IsZero(m.Members[i]) { // not required
			continue
		}

		if m.Members[i] != nil {
			if err := m.Members[i].Validate(formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("Members" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("Members" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

func (m *IdentityWebRequest) validateName(formats strfmt.Registry) error {
	if swag.IsZero(m.Name) { // not required
		return nil
	}

	if m.Name != nil {
		if err := m.Name.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("Name")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("Name")
			}
			return err
		}
	}

	return nil
}

// ContextValidate validate this identity web request based on the context it is used
func (m *IdentityWebRequest) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateContainer(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateGroup(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateID(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateMembers(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateName(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *IdentityWebRequest) contextValidateContainer(ctx context.Context, formats strfmt.Registry) error {

	if m.Container != nil {
		if err := m.Container.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("Container")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("Container")
			}
			return err
		}
	}

	return nil
}

func (m *IdentityWebRequest) contextValidateGroup(ctx context.Context, formats strfmt.Registry) error {

	if m.Group != nil {
		if err := m.Group.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("Group")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("Group")
			}
			return err
		}
	}

	return nil
}

func (m *IdentityWebRequest) contextValidateID(ctx context.Context, formats strfmt.Registry) error {

	if m.ID != nil {
		if err := m.ID.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("ID")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("ID")
			}
			return err
		}
	}

	return nil
}

func (m *IdentityWebRequest) contextValidateMembers(ctx context.Context, formats strfmt.Registry) error {

	for i := 0; i < len(m.Members); i++ {

		if m.Members[i] != nil {
			if err := m.Members[i].ContextValidate(ctx, formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("Members" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("Members" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

func (m *IdentityWebRequest) contextValidateName(ctx context.Context, formats strfmt.Registry) error {

	if m.Name != nil {
		if err := m.Name.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("Name")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("Name")
			}
			return err
		}
	}

	return nil
}

// MarshalBinary interface implementation
func (m *IdentityWebRequest) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *IdentityWebRequest) UnmarshalBinary(b []byte) error {
	var res IdentityWebRequest
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}