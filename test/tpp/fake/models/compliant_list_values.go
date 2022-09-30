// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"

	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
)

// CompliantListValues compliant list values
//
// swagger:model CompliantListValues
type CompliantListValues struct {

	// compliant
	Compliant bool `json:"Compliant,omitempty"`

	// values
	Values []string `json:"Values"`
}

// Validate validates this compliant list values
func (m *CompliantListValues) Validate(formats strfmt.Registry) error {
	return nil
}

// ContextValidate validates this compliant list values based on context it is used
func (m *CompliantListValues) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *CompliantListValues) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *CompliantListValues) UnmarshalBinary(b []byte) error {
	var res CompliantListValues
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}