package ecr

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParse(t *testing.T) {
	tests := map[string]*Registry{
		"public.ecr.aws": {
			Region:    "us-east-1",
			DNSSuffix: "public.ecr.aws",
		},
		"123456789012.dkr.ecr.us-west-2.amazonaws.com": {
			AccountID: "123456789012",
			Region:    "us-west-2",
			DNSSuffix: "amazonaws.com",
		},
		"123456789012.dkr.ecr-fips.us-west-2.amazonaws.com": {
			AccountID: "123456789012",
			Region:    "us-west-2",
			FIPS:      true,
			DNSSuffix: "amazonaws.com",
		},
		"invalid.ecr.us-west-2.amazonaws.com": nil,
	}
	for host, expected := range tests {
		host, expected := host, expected
		t.Run(host, func(t *testing.T) {
			t.Parallel()
			actual := Parse(host)
			assert.Equal(t, expected, actual)
		})
	}
}
