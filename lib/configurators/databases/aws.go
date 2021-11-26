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
	"context"
	"encoding/json"
	"fmt"
	"strings"

	awslib "github.com/gravitational/teleport/lib/cloud/aws"
	"github.com/gravitational/trace"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	awssession "github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/iam"
	"github.com/aws/aws-sdk-go/service/iam/iamiface"
	"github.com/aws/aws-sdk-go/service/sts"
	"github.com/aws/aws-sdk-go/service/sts/stsiface"
)

const (
	// defaultPolicyName default policy name.
	defaultPolicyName = "DatabaseAccess"
	// policyDescription
	policyDescription = "Used by Teleport database agents for discovering AWS-hosted databases."
	// boundarySuffix boundary policies will have this suffix.
	boundarySuffix = "-Boundary"
	// boundaryDescription
	boundaryDescription = "Boundary of the Teleport database agents policy."

	// rdsType constant name of RDS type.
	rdsType = "rds"
	// auroraType constant name of Aurora type.
	auroraType = "aurora"
)

// AWSTypes is a list with database types supported by the configurator
var AWSTypes = []string{rdsType, auroraType}

// targetType represents types that will have the policies attached to.
type targetType int

const (
	// targetTypeUser attach policies to Users.
	targetTypeUser targetType = iota
	// targetTypeRole attach policies to Roles.
	targetTypeRole
)

func (t targetType) String() string {
	switch t {
	case targetTypeUser:
		return "user"
	case targetTypeRole:
		return "role"
	default:
		return "unknown"
	}
}

// AWSManualInstrcutionsConfig configuration used to generate the formatted
// AWS policies and target.
type AWSManualInstructionsConfig struct {
	// Types comma-separated list of database types that the policies will give
	// access to.
	Types string
	// Role the AWS role that policies will be attached to.
	Role string
	// User the AWS user that policies will be attached to.
	User string

	targetType targetType
	target     string
	typesList  []string
}

func (c *AWSManualInstructionsConfig) CheckAndSetDefaults() error {
	if c.Types == "" {
		return trace.BadParameter("at least one type should be provided: %s", strings.Join(AWSTypes, ", "))
	}
	c.typesList = strings.Split(c.Types, ",")

	if c.User != "" {
		c.targetType = targetTypeUser
		c.target = c.User
	}

	if c.Role != "" {
		c.targetType = targetTypeRole
		c.target = c.Role
	}

	if c.target == "" {
		return trace.BadParameter("at least one should be present: user or role")
	}

	return nil
}

// AWSFormattedInformation has "human-readable" format of the AWS configurator
// information.
type AWSFormattedInformation struct {
	// PolicyName name of the policy that will be created.
	PolicyName string
	// PolicyDocument policy formatted in JSON with identation.
	PolicyDocument string
	// BoundaryName name of the boundary policy that will be created.
	BoundaryName string
	// BoundaryDocument boundary policy formatted in JSON with identation.
	BoundaryDocument string
	// Target name of the target that policies will be attached.
	Target string
	// TargetType target type in string format.
	TargetType string
}

// GetAWSFormattedInformation generates a `AWSFormattedInformation` without the
// necessity of connecting to AWS.
func GetAWSFormattedInformation(config AWSManualInstructionsConfig) (*AWSFormattedInformation, error) {
	err := config.CheckAndSetDefaults()
	if err != nil {
		return nil, trace.Wrap(err)
	}

	policyFormatted, err := formatPolicyDocument(policyDocument(config.targetType, config.typesList))
	if err != nil {
		return nil, trace.Wrap(err)
	}

	boundaryFormatted, err := formatPolicyDocument(boundaryDocument(config.targetType, config.typesList))
	if err != nil {
		return nil, trace.Wrap(err)
	}

	return &AWSFormattedInformation{
		PolicyDocument:   policyFormatted,
		BoundaryDocument: boundaryFormatted,
		Target:           config.target,
		TargetType:       config.targetType.String(),
	}, nil
}

// AWSConfiguratorConfig configurator config.
type AWSConfiguratorConfig struct {
	// PolicyName name of the policy that will be created.
	PolicyName string
	// Types comma-separated list of database types that the policies will give
	// access to.
	Types string
	// Role the AWS role that policies will be attached to.
	Role string
	// User the AWS user that policies will be attached to.
	User string

	boundaryName string
	targetType   targetType
	target       string
	typesList    []string
}

// CheckAndSetDefauls validates and set default values to the configuration.
func (c *AWSConfiguratorConfig) CheckAndSetDefaults(stsClient stsiface.STSAPI) error {
	if c.Types == "" {
		return trace.BadParameter("at least one type should be provided: %s", strings.Join(AWSTypes, ", "))
	}
	c.typesList = strings.Split(c.Types, ",")

	if c.PolicyName == "" {
		c.PolicyName = defaultPolicyName
	}

	if c.boundaryName == "" {
		c.boundaryName = fmt.Sprintf("%s%s", c.PolicyName, boundarySuffix)
	}

	if c.User != "" {
		c.targetType = targetTypeUser
		c.target = c.User
	}

	if c.Role != "" {
		c.targetType = targetTypeRole
		c.target = c.Role
	}

	if c.target != "" {
		return nil
	}

	// if either role or user are not provided, try to the current one (using
	// Security token service).
	identity, err := awslib.GetIdentityWithClient(context.Background(), stsClient)
	if err != nil {
		return trace.Wrap(err)
	}

	switch identity.(type) {
	case awslib.User:
		c.targetType = targetTypeUser
		c.target = identity.GetName()
	case awslib.Role:
		c.targetType = targetTypeRole
		c.target = identity.GetName()
	default:
		return trace.BadParameter("not able to identify the target role/user")
	}

	return nil
}

// AWSConfigurator struct responsible for setting up database access.
type AWSConfigurator struct {
	config           *AWSConfiguratorConfig
	policyDocument   *awslib.PolicyDocument
	boundaryDocument *awslib.PolicyDocument
	iamClient        iamiface.IAMAPI
}

// NewAWSConfigurator creates new instance of AWSConfigurator.
func NewAWSConfigurator(config *AWSConfiguratorConfig) (*AWSConfigurator, error) {
	session, err := awssession.NewSessionWithOptions(awssession.Options{
		SharedConfigState: awssession.SharedConfigEnable,
	})
	if err != nil {
		return nil, trace.Wrap(err)
	}

	stsClient := sts.New(session)
	err = config.CheckAndSetDefaults(stsClient)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	iamClient := iam.New(session)
	return &AWSConfigurator{
		config:           config,
		policyDocument:   policyDocument(config.targetType, config.typesList),
		boundaryDocument: boundaryDocument(config.targetType, config.typesList),
		iamClient:        iamClient,
	}, nil
}

// GetFormattedInformation returns the configuration information formatted.
func (c *AWSConfigurator) GetFormattedInformation() (*AWSFormattedInformation, error) {
	policyFormatted, err := formatPolicyDocument(c.policyDocument)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	boundaryFormatted, err := formatPolicyDocument(c.boundaryDocument)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	return &AWSFormattedInformation{
		PolicyName:       c.config.PolicyName,
		PolicyDocument:   policyFormatted,
		BoundaryName:     c.config.boundaryName,
		BoundaryDocument: boundaryFormatted,
		Target:           c.config.target,
		TargetType:       c.config.targetType.String(),
	}, nil
}

// CreatePolicy creates the IAM policy for database access at AWS.
func (c *AWSConfigurator) CreatePolicy() (string, error) {
	encodedPolicyDocument, err := encodePolicyDocument(c.policyDocument)
	if err != nil {
		return "", trace.Wrap(err)
	}

	resp, err := c.iamClient.CreatePolicyWithContext(context.Background(), &iam.CreatePolicyInput{
		Description:    aws.String(policyDescription),
		PolicyDocument: aws.String(encodedPolicyDocument),
		PolicyName:     aws.String(c.config.PolicyName),
	})
	if err != nil {
		return "", wrapAWSError(err)
	}

	return *resp.Policy.Arn, nil
}

// CreateBoundaryPolicy creates the IAM boundary policy for database access at
// AWS.
func (c *AWSConfigurator) CreateBoundaryPolicy() (string, error) {
	encodedPolicyDocument, err := encodePolicyDocument(c.boundaryDocument)
	if err != nil {
		return "", trace.Wrap(err)
	}

	resp, err := c.iamClient.CreatePolicyWithContext(context.Background(), &iam.CreatePolicyInput{
		Description:    aws.String(boundaryDescription),
		PolicyDocument: aws.String(encodedPolicyDocument),
		PolicyName:     aws.String(c.config.boundaryName),
	})
	if err != nil {
		return "", wrapAWSError(err)
	}

	return *resp.Policy.Arn, nil
}

// AttachPolicyAndBoundary attaches the `policyArn` and set `boundaryArn` as a
// permission boundary to the target (user or role).
func (c *AWSConfigurator) AttachPolicyAndBoundary(policyArn, boundaryArn string) error {
	switch c.config.targetType {
	case targetTypeUser:
		_, err := c.iamClient.AttachUserPolicy(&iam.AttachUserPolicyInput{
			PolicyArn: aws.String(policyArn),
			UserName:  aws.String(c.config.target),
		})
		if err != nil {
			return wrapAWSError(err)
		}

		_, err = c.iamClient.PutUserPermissionsBoundary(&iam.PutUserPermissionsBoundaryInput{
			PermissionsBoundary: aws.String(boundaryArn),
			UserName:            aws.String(c.config.target),
		})
		if err != nil {
			return wrapAWSError(err)
		}
	case targetTypeRole:
		_, err := c.iamClient.AttachRolePolicy(&iam.AttachRolePolicyInput{
			PolicyArn: aws.String(policyArn),
			RoleName:  aws.String(c.config.target),
		})
		if err != nil {
			return trace.Wrap(err)
		}

		_, err = c.iamClient.PutRolePermissionsBoundary(&iam.PutRolePermissionsBoundaryInput{
			PermissionsBoundary: aws.String(boundaryArn),
			RoleName:            aws.String(c.config.target),
		})
		if err != nil {
			return wrapAWSError(err)
		}
	}

	return nil
}

// formatPolicyDocument formats the PolicyDocument in a "friendly" format, which
// can be presented to end users.
func formatPolicyDocument(policy *awslib.PolicyDocument) (string, error) {
	b, err := json.MarshalIndent(policy, "", "    ")
	if err != nil {
		return "", trace.Wrap(err)
	}

	return string(b), nil
}

// encodePolicyDocument encode PolicyDocument into JSON.
func encodePolicyDocument(policy *awslib.PolicyDocument) (string, error) {
	b, err := json.Marshal(policy)
	if err != nil {
		return "", trace.Wrap(err)
	}

	return string(b), nil
}

// List of actions that will be present at the policies (according to the
// configuration).
var (
	userBaseActions      = []string{"iam:GetUserPolicy", "iam:PutUserPolicy", "iam:DeleteUserPolicy"}
	roleBaseActions      = []string{"iam:GetRolePolicy", "iam:PutRolePolicy", "iam:DeleteRolePolicy"}
	rdsActions           = []string{"rds:DescribeDBInstances", "rds:ModifyDBInstance"}
	auroraActions        = []string{"rds:DescribeDBClusters", "rds:ModifyDBCluster"}
	boundaryExtraActions = []string{"rds-db:connect"}
)

// iamDocument generates an PolicyDocument based on the configuration provided.
func iamDocument(targetType targetType, types, extraActions []string) *awslib.PolicyDocument {
	var actions []string
	switch targetType {
	case targetTypeUser:
		actions = make([]string, len(userBaseActions))
		copy(actions, userBaseActions)
	case targetTypeRole:
		actions = make([]string, len(roleBaseActions))
		copy(actions, roleBaseActions)
	}

	for _, databaseType := range types {
		switch databaseType {
		case auroraType:
			actions = append(actions, auroraActions...)
		case rdsType:
			actions = append(actions, rdsActions...)
		default:
		}
	}

	actions = append(actions, extraActions...)

	doc := awslib.NewPolicyDocument()
	doc.Statements = []*awslib.Statement{
		{
			Effect:    awslib.EffectAllow,
			Actions:   actions,
			Resources: []string{"*"},
		},
	}

	return doc
}

// policyDocument shortcut for generating policy document.
func policyDocument(targetType targetType, types []string) *awslib.PolicyDocument {
	return iamDocument(targetType, types, []string{})
}

// policyDocument shortcut for generating boundary policy document.
func boundaryDocument(targetType targetType, types []string) *awslib.PolicyDocument {
	return iamDocument(targetType, types, boundaryExtraActions)
}

// wrapAWSError wraps an AWS error accordingly.
func wrapAWSError(err error) error {
	switch e := err.(type) {
	case awserr.RequestFailure:
		return awslib.ConvertAWSRequestFailureError(e)
	default:
		return trace.Wrap(err)
	}
}
