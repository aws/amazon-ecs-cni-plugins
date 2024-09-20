// Copyright 2017 Amazon.com, Inc. or its affiliates. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License"). You may
// not use this file except in compliance with the License. A copy of the
// License is located at
//
//     http://aws.amazon.com/apache2.0/
//
// or in the "license" file accompanying this file. This file is distributed
// on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
// express or implied. See the License for the specific language governing
// permissions and limitations under the License.

package ec2metadata

import (
	"context"
	"io"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/feature/ec2/imds"
)

// EC2Metadata wraps the methods from the amazon-sdk-go's ec2metadata package
type EC2Metadata interface {
	GetMetadata(path string) (string, error)
	Region() (string, error)
}

type ec2Metadata struct {
	imds *imds.Client
}

// NewEC2Metadata creates a new EC2Metadata object
func NewEC2Metadata() (EC2Metadata, error) {
	cfg, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		return nil, err
	}

	return &ec2Metadata{
		imds: imds.NewFromConfig(cfg),
	}, nil
}

func (e *ec2Metadata) GetMetadata(path string) (string, error) {
	output, err := e.imds.GetMetadata(context.TODO(), &imds.GetMetadataInput{
		Path: path,
	})
	if err != nil {
		return "", err
	}

	content, err := io.ReadAll(output.Content)
	if err != nil {
		return "", err
	}

	return string(content), nil
}

func (e *ec2Metadata) Region() (string, error) {
	output, err := e.imds.GetRegion(context.TODO(), &imds.GetRegionInput{})
	if err != nil {
		return "", err
	}

	return output.Region, nil
}
