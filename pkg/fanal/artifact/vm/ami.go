package vm

import (
	"context"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/fanal/types"
)

type AMI struct {
	*EBS

	imageID string
}

func newAMI(imageID string, storage Storage, region, endpoint string) (*AMI, error) {
	return nil, xerrors.New("pkg/cloud not implemented")
}

func (a *AMI) Inspect(ctx context.Context) (types.ArtifactReference, error) {
	ref, err := a.EBS.Inspect(ctx)
	if err != nil {
		return types.ArtifactReference{}, err
	}
	ref.Name = a.imageID
	return ref, nil
}
