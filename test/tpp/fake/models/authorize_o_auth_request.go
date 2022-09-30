// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"

	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
)

// AuthorizeOAuthRequest authorize o auth request
//
// swagger:model AuthorizeOAuthRequest
type AuthorizeOAuthRequest struct {

	// client id
	ClientID string `json:"client_id,omitempty"`

	// password
	Password string `json:"password,omitempty"`

	// redirect uri
	RedirectURI string `json:"redirect_uri,omitempty"`

	// scope
	Scope string `json:"scope,omitempty"`

	// state
	State string `json:"state,omitempty"`

	// username
	Username string `json:"username,omitempty"`
}

// Validate validates this authorize o auth request
func (m *AuthorizeOAuthRequest) Validate(formats strfmt.Registry) error {
	return nil
}

// ContextValidate validates this authorize o auth request based on context it is used
func (m *AuthorizeOAuthRequest) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *AuthorizeOAuthRequest) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *AuthorizeOAuthRequest) UnmarshalBinary(b []byte) error {
	var res AuthorizeOAuthRequest
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
