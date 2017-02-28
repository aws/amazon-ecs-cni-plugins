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

package commands

type unmappedIPV4AddressError struct {
	operation string
	origin    string
	message   string
}

func (err *unmappedIPV4AddressError) Error() string {
	return err.operation + " " + err.origin + ": " + err.message
}

func newUnmappedIPV4AddressError(operation string, origin string, message string) error {
	return &unmappedIPV4AddressError{
		operation: operation,
		origin:    origin,
		message:   message,
	}
}
