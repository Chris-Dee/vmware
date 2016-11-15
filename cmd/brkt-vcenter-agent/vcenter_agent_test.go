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
