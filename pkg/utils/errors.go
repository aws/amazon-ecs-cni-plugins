// Copyright 2017 Amazon.com, Inc. or its affiliates. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License"). You may
// not use this file except in compliance with the License. A copy of the
// License is located at
//
//	http://aws.amazon.com/apache2.0/
//
// or in the "license" file accompanying this file. This file is distributed
// on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
// express or implied. See the License for the specific language governing
// permissions and limitations under the License.

package utils

// Retriable definies the interface for retriable object
type Retriable interface {
	Retry() bool
}

// DefaultRetriable is a simple struct that implements the Retriable
type DefaultRetriable struct {
	retry bool
}

// Retry returns whether should retry or not
func (dr DefaultRetriable) Retry() bool {
	return dr.retry
}

// NewRetriable creates a simple Retriable object
func NewRetriable(retry bool) Retriable {
	return DefaultRetriable{
		retry: retry,
	}
}

// RetriableError definies the interface for retriable error
type RetriableError interface {
	Retriable
	error
}

// DefaultRetriableError is a simple struct that implements the RetriableError
type DefaultRetriableError struct {
	Retriable
	error
}

// NewRetriableError creates a simple RetriableError object
func NewRetriableError(retriable Retriable, err error) RetriableError {
	return &DefaultRetriableError{
		retriable,
		err,
	}
}
