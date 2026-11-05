package builtin

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/threagile/threagile/pkg/types"
)

func sharedStoreModel(readonlyOfSecond bool, secondBoundary string) *types.Model {
	store := ptAsset("db", ptTech(types.Database))
	store.Type = types.Datastore
	a := ptAsset("a", ptTech(types.WebApplication))
	b := ptAsset("b", ptTech(types.WebApplication))
	second := ptLink("l2", "b", "db", types.JdbcEncrypted)
	second.Readonly = readonlyOfSecond
	return ptModel([]*types.TechnicalAsset{store, a, b},
		[]*types.CommunicationLink{ptLink("l1", "a", "db", types.JdbcEncrypted), second},
		map[string]*types.TrustBoundary{"a": ptBoundary("tb1", types.NetworkOnPrem), "b": ptBoundary(secondBoundary, types.NetworkOnPrem)})
}

func TestSharedDatastoreTamperingWritersInTwoBoundariesCreateRisk(t *testing.T) {
	risks, err := NewSharedDatastoreTamperingRule().GenerateRisks(sharedStoreModel(false, "tb2"))

	require.NoError(t, err)
	require.Len(t, risks, 1)
	assert.Equal(t, "shared-datastore-tampering@db", risks[0].SyntheticId)
}

func TestSharedDatastoreTamperingNoRiskForReadonlyOrSameBoundary(t *testing.T) {
	risks, err := NewSharedDatastoreTamperingRule().GenerateRisks(sharedStoreModel(true, "tb2"))
	require.NoError(t, err)
	assert.Empty(t, risks, "second accessor is readonly")

	risks, err = NewSharedDatastoreTamperingRule().GenerateRisks(sharedStoreModel(false, "tb1"))
	require.NoError(t, err)
	assert.Empty(t, risks, "both writers in the same boundary")
}
