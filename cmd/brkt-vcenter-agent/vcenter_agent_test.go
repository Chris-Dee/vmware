// Copyright 2016 Bracket Computing, Inc. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License").
// You may not use this file except in compliance with the License.
// A copy of the License is located at
//
// https://github.com/brkt/brkt-cli/blob/master/LICENSE
//
// or in the "license" file accompanying this file. This file is
// distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
// CONDITIONS OF ANY KIND, either express or implied. See the
// License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"testing"
	"github.com/vmware/govmomi/vim25/types"
	"github.com/stretchr/testify/assert"
)

func TestDedupe(t *testing.T) {
	refs := []types.ManagedObjectReference{
		{Value: "1"},
		{Value: "2"},
		{Value: "2"},
	}
	deduped := dedupe(refs)
	assert.Equal(t, 2, len(deduped))
	assert.Equal(t, "1", deduped[0].Value)
	assert.Equal(t, "2", deduped[1].Value)
}
