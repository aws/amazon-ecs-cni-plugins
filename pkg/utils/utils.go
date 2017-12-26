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

package utils

import (
	"context"
	"reflect"
	"time"
)

// ZeroOrNil checks if the passed in interface is empty
func ZeroOrNil(obj interface{}) bool {
	if obj == nil {
		return true
	}

	// IsValid returns false if value is the zero Value
	value := reflect.ValueOf(obj)
	if !value.IsValid() {
		return true
	}

	// For array, slice, map check if the length is 0
	switch value.Kind() {
	case reflect.Slice, reflect.Array, reflect.Map:
		return value.Len() == 0
	}

	if !value.Type().Comparable() {
		return false
	}

	// Create the zero valued the type and compare
	zero := reflect.Zero(reflect.TypeOf(obj))
	if obj == zero.Interface() {
		return true
	}
	return false
}

// RetryWithBackoff takes a Backoff and a function to call that returns an error
// If the error is nil then the function will no longer be called
// If the error is Retriable then that will be used to determine if it should be
// retried
func RetryWithBackoff(backoff Backoff, fn func() error) error {
	return RetryWithBackoffCtx(context.Background(), backoff, fn)
}

// RetryWithBackoffCtx takes a context, a Backoff, and a function to call that returns an error
// If the context is done, nil will be returned
// If the error is nil then the function will no longer be called
// If the error is Retriable then that will be used to determine if it should be
// retried
func RetryWithBackoffCtx(ctx context.Context, backoff Backoff, fn func() error) error {
	var err error
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		err = fn()
		retriableErr, isRetriableErr := err.(Retriable)
		if err == nil || (isRetriableErr && !retriableErr.Retry()) {
			return err
		}

		time.Sleep(backoff.Duration())
	}
	return err
}
