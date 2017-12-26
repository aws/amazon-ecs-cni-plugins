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
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestZeroOrNil(t *testing.T) {
	type ZeroTest struct {
		testInt int
		TestStr string
	}

	var strMap map[string]string

	testCases := []struct {
		param    interface{}
		expected bool
		name     string
	}{
		{nil, true, "Nil is nil"},
		{0, true, "0 is 0"},
		{"", true, "\"\" is the string zerovalue"},
		{ZeroTest{}, true, "ZeroTest zero-value should be zero"},
		{ZeroTest{TestStr: "asdf"}, false, "ZeroTest with a field populated isn't zero"},
		{1, false, "1 is not 0"},
		{[]uint16{1, 2, 3}, false, "[1,2,3] is not zero"},
		{[]uint16{}, true, "[] is zero"},
		{struct{ uncomparable []uint16 }{uncomparable: []uint16{1, 2, 3}}, false, "Uncomparable structs are never zero"},
		{struct{ uncomparable []uint16 }{uncomparable: nil}, false, "Uncomparable structs are never zero"},
		{strMap, true, "map[string]string is zero or nil"},
		{make(map[string]string), true, "empty map[string]string is zero or nil"},
		{map[string]string{"foo": "bar"}, false, "map[string]string{foo:bar} is not zero or nil"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, ZeroOrNil(tc.param), tc.name)
		})
	}
}

func TestRetryWithBackoff(t *testing.T) {
	t.Run("retries", func(t *testing.T) {
		counter := 3
		RetryWithBackoff(NewSimpleBackoff(10*time.Millisecond, 10*time.Millisecond, 0, 1), func() error {
			if counter == 0 {
				return nil
			}
			counter--
			return errors.New("err")
		})
		assert.Equal(t, 0, counter, "Counter didn't go to 0; didn't get retried enough")
	})

	t.Run("no retries", func(t *testing.T) {
		counter := 3
		RetryWithBackoff(NewSimpleBackoff(10*time.Second, 20*time.Second, 0, 2), func() error {
			counter--
			return NewRetriableError(NewRetriable(false), errors.New("can't retry"))
		})
		assert.Equal(t, 2, counter, "Counter should only be operated once without retry")
	})
}

func TestRetryWithBackoffCtx(t *testing.T) {
	t.Run("retries", func(t *testing.T) {
		counter := 3
		RetryWithBackoffCtx(context.TODO(), NewSimpleBackoff(100*time.Millisecond, 100*time.Millisecond, 0, 1), func() error {
			if counter == 0 {
				return nil
			}
			counter--
			return errors.New("err")
		})
		assert.Equal(t, 0, counter, "Counter didn't go to 0; didn't get retried enough")
	})

	t.Run("no retries", func(t *testing.T) {
		counter := 3
		ctx, cancel := context.WithCancel(context.TODO())
		cancel()
		err := RetryWithBackoffCtx(ctx, NewSimpleBackoff(10*time.Second, 20*time.Second, 0, 2), func() error {
			counter--
			return NewRetriableError(NewRetriable(false), errors.New("can't retry"))
		})
		assert.Equal(t, 3, counter, "Counter should not be operated with context canceled")
		assert.Error(t, err)
	})

	t.Run("cancel context", func(t *testing.T) {
		counter := 2
		ctx, cancel := context.WithCancel(context.TODO())
		RetryWithBackoffCtx(ctx, NewSimpleBackoff(100*time.Millisecond, 100*time.Millisecond, 0, 1), func() error {
			counter--
			if counter == 0 {
				cancel()
			}
			return errors.New("err")
		})
		assert.Equal(t, 0, counter, "Counter not 0; went the wrong number of times")
	})
}
