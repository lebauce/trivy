package policy

import (
	"context"
	"fmt"
	"time"

	"golang.org/x/xerrors"
	"k8s.io/utils/clock"

	"github.com/aquasecurity/trivy/pkg/oci"
)

const (
	BundleVersion    = 0 // Latest released MAJOR version for trivy-policies
	BundleRepository = "ghcr.io/aquasecurity/trivy-policies"
)

type options struct {
	artifact *oci.Artifact
	clock    clock.Clock
}

// WithOCIArtifact takes an OCI artifact
func WithOCIArtifact(art *oci.Artifact) Option {
	return func(opts *options) {
		opts.artifact = art
	}
}

// WithClock takes a clock
func WithClock(c clock.Clock) Option {
	return func(opts *options) {
		opts.clock = c
	}
}

// Option is a functional option
type Option func(*options)

// Client implements policy operations
type Client struct {
	*options
	policyDir        string
	policyBundleRepo string
	quiet            bool
}

// Metadata holds default policy metadata
type Metadata struct {
	Digest       string
	DownloadedAt time.Time
}

func (m Metadata) String() string {
	return fmt.Sprintf(`Policy Bundle:
  Digest: %s
  DownloadedAt: %s
`, m.Digest, m.DownloadedAt.UTC())
}

// NewClient is the factory method for policy client
func NewClient(cacheDir string, quiet bool, policyBundleRepo string, opts ...Option) (*Client, error) {
	return nil, xerrors.New("pkg/policy not implemented")
}

// DownloadBuiltinPolicies download default policies from GitHub Pages
func (c *Client) DownloadBuiltinPolicies(ctx context.Context) error {
	return xerrors.New("pkg/policy not implemented")
}

// LoadBuiltinPolicies loads default policies
func (c *Client) LoadBuiltinPolicies() ([]string, error) {
	return nil, xerrors.New("pkg/policy not implemented")
}

// NeedsUpdate returns if the default policy should be updated
func (c *Client) NeedsUpdate(ctx context.Context) (bool, error) {
	return false, xerrors.New("pkg/policy not implemented")
}

func (c *Client) GetMetadata() (*Metadata, error) {
	return nil, xerrors.New("pkg/policy not implemented")
}

func (c *Client) Clear() error {
	return xerrors.New("pkg/policy not implemented")
}
