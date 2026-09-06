package controller

import (
	"errors"
	"fmt"

	"github.com/mgruszkiewicz/go-backblaze"
)

func StringSlicesEqual(a, b []backblaze.LifecycleRule) bool {
	if len(a) != len(b) {
		return false
	}
	for i, v := range a {
		if v != b[i] {
			return false
		}
	}
	return true
}

// safeProviderError deliberately excludes the provider's free-form message,
// which can contain request details that must not reach logs, Events, or status.
func safeProviderError(err error) error {
	var b2err *backblaze.B2Error
	if errors.As(err, &b2err) {
		if safeProviderCode(b2err.Code) {
			return fmt.Errorf("provider request failed (code %q, status %d)", b2err.Code, b2err.Status)
		}
		return fmt.Errorf("provider request failed (status %d)", b2err.Status)
	}
	return errors.New("provider request failed")
}

func safeProviderCode(code string) bool {
	if code == "" || len(code) > 64 {
		return false
	}
	for _, char := range code {
		if (char < 'a' || char > 'z') && (char < 'A' || char > 'Z') && (char < '0' || char > '9') && char != '_' && char != '-' {
			return false
		}
	}
	return true
}

func isProviderNotFound(err error) bool {
	var b2err *backblaze.B2Error
	return errors.As(err, &b2err) && (b2err.Status == 404 || b2err.Code == "not_found")
}

func isDefinitiveProviderRejection(err error) bool {
	var b2err *backblaze.B2Error
	return errors.As(err, &b2err) && b2err.Status >= 400 && b2err.Status < 500 && b2err.Status != 408 && b2err.Status != 429
}
