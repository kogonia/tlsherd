package domain

import "errors"

var (
	ErrNotFound            = errors.New("not found")
	ErrConflict            = errors.New("conflict")
	ErrForbidden           = errors.New("forbidden")
	ErrUnauthorized        = errors.New("unauthorized")
	ErrInvalid             = errors.New("invalid")
	ErrDomainMismatch      = errors.New("certificate domain mismatch")
	ErrLastAdmin           = errors.New("cannot remove or demote the last active admin")
	ErrSelfModification    = errors.New("cannot modify own account this way")
	ErrIdentityMismatch    = errors.New("agent identity mismatch")
	ErrConfirmRequired     = errors.New("confirmation required")
	ErrCertificateInUse    = errors.New("certificate is current for a domain")
	ErrKeyCertMismatch     = errors.New("private key does not match certificate")
	ErrMustChangePassword  = errors.New("password change required")
)
