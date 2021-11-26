/*
Copyright 2021 Gravitational, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package databases

import (
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/request"
	"github.com/aws/aws-sdk-go/service/iam"
	"github.com/aws/aws-sdk-go/service/iam/iamiface"
	"github.com/aws/aws-sdk-go/service/sts"
	"github.com/aws/aws-sdk-go/service/sts/stsiface"
	"github.com/stretchr/testify/require"
)

func TestManualInstructionsConfig(t *testing.T) {
	testCases := map[string]struct {
		config             *AWSManualInstructionsConfig
		expectedTypesList  []string
		expectedTarget     string
		expectedTargetType targetType
	}{
		"UserInstructions": {
			config: &AWSManualInstructionsConfig{
				Types: "sample",
				User:  "alice",
			},
			expectedTypesList:  []string{"sample"},
			expectedTarget:     "alice",
			expectedTargetType: targetTypeUser,
		},
		"RoleInstructions": {
			config: &AWSManualInstructionsConfig{
				Types: "sample",
				Role:  "alice",
			},
			expectedTypesList:  []string{"sample"},
			expectedTarget:     "alice",
			expectedTargetType: targetTypeRole,
		},
		"MultipleTypes": {
			config: &AWSManualInstructionsConfig{
				Types: "sample,type",
				Role:  "alice",
			},
			expectedTypesList:  []string{"sample", "type"},
			expectedTarget:     "alice",
			expectedTargetType: targetTypeRole,
		},
	}

	for name, test := range testCases {
		t.Run(name, func(t *testing.T) {
			err := test.config.CheckAndSetDefaults()
			require.NoError(t, err)
			require.ElementsMatch(t, test.expectedTypesList, test.config.typesList)
			require.Equal(t, test.expectedTarget, test.config.target)
			require.Equal(t, test.expectedTargetType, test.config.targetType)
		})
	}

	t.Run("EmptyTarget", func(t *testing.T) {
		config := &AWSManualInstructionsConfig{Types: "sample"}
		err := config.CheckAndSetDefaults()
		require.Error(t, err)
	})

	t.Run("EmptyTypes", func(t *testing.T) {
		config := &AWSManualInstructionsConfig{Types: ""}
		err := config.CheckAndSetDefaults()
		require.Error(t, err)
	})
}

func TestAWSConfiguratorConfig(t *testing.T) {
	testCases := map[string]struct {
		config               *AWSConfiguratorConfig
		stsClient            *STSMock
		expectedTarget       string
		expectedTargetType   targetType
		expectedTypes        []string
		expectedPolicyName   string
		expectedBoundaryName string
	}{
		"User": {
			config: &AWSConfiguratorConfig{
				PolicyName: "test",
				User:       "alice",
				Types:      "sample",
			},
			stsClient:            &STSMock{},
			expectedTarget:       "alice",
			expectedTargetType:   targetTypeUser,
			expectedTypes:        []string{"sample"},
			expectedPolicyName:   "test",
			expectedBoundaryName: "test-Boundary",
		},
		"Role": {
			config: &AWSConfiguratorConfig{
				PolicyName: "test",
				Role:       "ec2",
				Types:      "sample",
			},
			stsClient:            &STSMock{},
			expectedTarget:       "ec2",
			expectedTargetType:   targetTypeRole,
			expectedTypes:        []string{"sample"},
			expectedPolicyName:   "test",
			expectedBoundaryName: "test-Boundary",
		},
		"CurrentUser": {
			config: &AWSConfiguratorConfig{
				PolicyName: "test",
				Types:      "sample",
			},
			stsClient:            &STSMock{ARN: "arn:aws:iam::123456789012:user/alice"},
			expectedTarget:       "alice",
			expectedTargetType:   targetTypeUser,
			expectedTypes:        []string{"sample"},
			expectedPolicyName:   "test",
			expectedBoundaryName: "test-Boundary",
		},
		"CurrentRole": {
			config: &AWSConfiguratorConfig{
				PolicyName: "test",
				Types:      "sample",
			},
			stsClient:            &STSMock{ARN: "arn:aws:iam::123456789012:role/ec2"},
			expectedTarget:       "ec2",
			expectedTargetType:   targetTypeRole,
			expectedTypes:        []string{"sample"},
			expectedPolicyName:   "test",
			expectedBoundaryName: "test-Boundary",
		},
		"MultipleTypes": {
			config: &AWSConfiguratorConfig{
				PolicyName: "test",
				User:       "alice",
				Types:      "sample,another",
			},
			stsClient:            &STSMock{},
			expectedTarget:       "alice",
			expectedTargetType:   targetTypeUser,
			expectedTypes:        []string{"sample", "another"},
			expectedPolicyName:   "test",
			expectedBoundaryName: "test-Boundary",
		},
	}

	for name, test := range testCases {
		t.Run(name, func(t *testing.T) {
			err := test.config.CheckAndSetDefaults(test.stsClient)
			require.NoError(t, err)
			require.Equal(t, test.expectedTarget, test.config.target)
			require.Equal(t, test.expectedTargetType, test.config.targetType)
			require.ElementsMatch(t, test.expectedTypes, test.config.typesList)
			require.Equal(t, test.expectedPolicyName, test.config.PolicyName)
			require.Equal(t, test.expectedBoundaryName, test.config.boundaryName)
		})
	}

	t.Run("GeneratePolicyName", func(t *testing.T) {
		config := &AWSConfiguratorConfig{User: "alice", Types: "sample,another"}
		err := config.CheckAndSetDefaults(&STSMock{})
		require.NoError(t, err)
		require.NotEmpty(t, config.PolicyName)
		require.True(t, strings.HasPrefix(config.boundaryName, config.PolicyName))
	})
}

func TestAWSConfigurator(t *testing.T) {
	testCases := map[string]struct {
		config       *AWSConfiguratorConfig
		attachToUser bool
		attachToRole bool
	}{
		"User": {
			config:       &AWSConfiguratorConfig{Types: "rds", User: "alice"},
			attachToUser: true,
		},
		"Role": {
			config:       &AWSConfiguratorConfig{Types: "rds", Role: "ec2"},
			attachToRole: true,
		},
	}

	for name, test := range testCases {
		t.Run(name, func(t *testing.T) {
			configurator, err := NewAWSConfigurator(test.config)
			require.NoError(t, err)

			expectedPolicyArn := "arn:aws:iam::123456789012:policy/test"
			expectedBoundaryArn := "arn:aws:iam::123456789012:policy/testBoundary"

			configurator.iamClient = &IAMMock{
				PolicyArn:    expectedPolicyArn,
				BoundaryArn:  expectedBoundaryArn,
				AttachToUser: test.attachToUser,
				AttachToRole: test.attachToRole,
			}

			policyArn, err := configurator.CreatePolicy()
			require.NoError(t, err)
			require.Equal(t, expectedPolicyArn, policyArn)

			boundaryArn, err := configurator.CreateBoundaryPolicy()
			require.NoError(t, err)
			require.Equal(t, expectedBoundaryArn, boundaryArn)

			err = configurator.AttachPolicyAndBoundary(policyArn, boundaryArn)
			require.NoError(t, err)
		})
	}
}

type STSMock struct {
	stsiface.STSAPI
	ARN string
}

func (m *STSMock) GetCallerIdentityWithContext(aws.Context, *sts.GetCallerIdentityInput, ...request.Option) (*sts.GetCallerIdentityOutput, error) {
	return &sts.GetCallerIdentityOutput{
		Arn: aws.String(m.ARN),
	}, nil
}

type IAMMock struct {
	iamiface.IAMAPI

	PolicyArn   string
	BoundaryArn string

	AttachToUser      bool
	AttachToRole      bool
	CreatePolicyError error
}

func (m *IAMMock) CreatePolicyWithContext(_ aws.Context, input *iam.CreatePolicyInput, _ ...request.Option) (*iam.CreatePolicyOutput, error) {
	arn := m.PolicyArn
	if strings.HasSuffix(*input.PolicyName, boundarySuffix) {
		arn = m.BoundaryArn
	}

	return &iam.CreatePolicyOutput{
		Policy: &iam.Policy{
			Arn: aws.String(arn),
		},
	}, m.CreatePolicyError
}

func (m *IAMMock) AttachUserPolicy(_ *iam.AttachUserPolicyInput) (*iam.AttachUserPolicyOutput, error) {
	if !m.AttachToUser {
		return nil, awserr.New("501", "not implemented", nil)
	}

	return &iam.AttachUserPolicyOutput{}, nil
}

func (m *IAMMock) PutUserPermissionsBoundary(_ *iam.PutUserPermissionsBoundaryInput) (*iam.PutUserPermissionsBoundaryOutput, error) {
	if !m.AttachToUser {
		return nil, awserr.New("501", "not implemented", nil)
	}

	return &iam.PutUserPermissionsBoundaryOutput{}, nil
}

func (m *IAMMock) AttachRolePolicy(_ *iam.AttachRolePolicyInput) (*iam.AttachRolePolicyOutput, error) {
	if !m.AttachToRole {
		return nil, awserr.New("501", "not implemented", nil)
	}

	return &iam.AttachRolePolicyOutput{}, nil
}

func (m *IAMMock) PutRolePermissionsBoundary(_ *iam.PutRolePermissionsBoundaryInput) (*iam.PutRolePermissionsBoundaryOutput, error) {
	if !m.AttachToRole {
		return nil, awserr.New("501", "not implemented", nil)
	}

	return &iam.PutRolePermissionsBoundaryOutput{}, nil
}
