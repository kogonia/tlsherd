package authz

import (
	"testing"

	"github.com/kogonia/tlsherd/internal/domain"
)

func TestNormalizePerm(t *testing.T) {
	p := &domain.GroupPermission{CanWriteCerts: true}
	NormalizePerm(p)
	if !p.CanRead {
		t.Fatal("write implies read")
	}
}
