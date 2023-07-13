// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"

	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
)

// RefreshOAuthRequest refresh o auth request
//
// swagger:model RefreshOAuthRequest
type RefreshOAuthRequest struct {

	// client id
	ClientID string `json:"client_id,omitempty"`

	// refresh token
	RefreshToken string `json:"refresh_token,omitempty"`
}

// Validate validates this refresh o auth request
func (m *RefreshOAuthRequest) Validate(formats strfmt.Registry) error {
	return nil
}

// ContextValidate validates this refresh o auth request based on context it is used
func (m *RefreshOAuthRequest) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *RefreshOAuthRequest) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *RefreshOAuthRequest) UnmarshalBinary(b []byte) error {
	var res RefreshOAuthRequest
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
