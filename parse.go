package ecr

import "regexp"

const ecrPublicDomain = "public.ecr.aws"

var ecrDomainPattern = regexp.MustCompile(`^(\d{12})\.dkr\.ecr(\-fips)?\.([a-zA-Z0-9][a-zA-Z0-9-_]*)\.(amazonaws\.com(?:\.cn)?|sc2s\.sgov\.gov|c2s\.ic\.gov|cloud\.adc-e\.uk|csp\.hci\.ic\.gov)$`)

// Registry is a extracted details from a valid ECR hostname.
type Registry struct {
	AccountID string
	Region    string
	FIPS      bool
	DNSSuffix string
}

// String implements fmt.Stringer reconstructing the original ECR hostname.
func (r *Registry) String() string {
	if r.DNSSuffix == ecrPublicDomain {
		return ecrPublicDomain
	}
	if r.FIPS {
		return r.AccountID + ".dkr.ecr-fips." + r.Region + "." + r.DNSSuffix
	}
	return r.AccountID + ".dkr.ecr." + r.Region + "." + r.DNSSuffix
}

// Parse the given ECR hostname extracting the details, returns nil if the hostname is invalid.
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
		AccountID: matches[1],
		Region:    matches[3],
		FIPS:      matches[2] == "-fips",
		DNSSuffix: matches[4],
	}
}
