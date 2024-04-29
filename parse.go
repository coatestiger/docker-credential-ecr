package ecr

import "regexp"

const ecrPublicDomain = "public.ecr.aws"

var ecrDomainPattern = regexp.MustCompile(`^(\d{12})\.dkr\.ecr(\-fips)?\.([a-zA-Z0-9][a-zA-Z0-9-_]*)\.(amazonaws\.com(?:\.cn)?|sc2s\.sgov\.gov|c2s\.ic\.gov|cloud\.adc-e\.uk|csp\.hci\.ic\.gov)$`)

// Registry is a parsed details from a valid ECR registry hostname.
type Registry struct {
	ID        string
	Region    string
	FIPS      bool
	DNSSuffix string
}

// String implements fmt.Stringer.
func (r *Registry) String() string {
	if r.DNSSuffix == ecrPublicDomain {
		return ecrPublicDomain
	}
	if r.FIPS {
		return r.ID + ".dkr.ecr-fips." + r.Region + "." + r.DNSSuffix
	}
	return r.ID + ".dkr.ecr." + r.Region + "." + r.DNSSuffix
}

// Parse parses the given hostname and returns a Registry.
func Parse(hostname string) *Registry {
	if hostname == ecrPublicDomain {
		return &Registry{
			Region:    "us-east-1",
			DNSSuffix: ecrPublicDomain,
		}
	}
	matches := ecrDomainPattern.FindStringSubmatch(hostname)
	if matches == nil {
		return nil
	}
	return &Registry{
		ID:        matches[1],
		Region:    matches[3],
		FIPS:      matches[2] == "-fips",
		DNSSuffix: matches[4],
	}
}
