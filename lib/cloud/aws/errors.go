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

package aws

import (
	"net/http"

	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/gravitational/trace"
)

// ConvertAWSRequestFailureError converts AWS RequestFailure errors to trace errors.
func ConvertAWSRequestFailureError(err awserr.RequestFailure) error {
	switch err.StatusCode() {
	case http.StatusForbidden:
		return trace.AccessDenied(err.Error())
	case http.StatusConflict:
		return trace.AlreadyExists(err.Error())
	case http.StatusNotFound:
		return trace.NotFound(err.Error())
	}
	return err // Return unmodified.
}
