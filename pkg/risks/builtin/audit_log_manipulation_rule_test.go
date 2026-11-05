package builtin

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/threagile/threagile/pkg/types"
)

func TestAuditLogManipulationWriteFromOtherBoundaryCreatesRisk(t *testing.T) {
	monitoring := ptAsset("log", ptTech(types.Monitoring))
	app := ptAsset("app", ptTech(types.WebApplication))
	model := ptModel([]*types.TechnicalAsset{monitoring, app}, []*types.CommunicationLink{ptLink("l", "app", "log", types.HTTPS)},
		map[string]*types.TrustBoundary{"log": ptBoundary("tb1", types.NetworkOnPrem), "app": ptBoundary("tb2", types.NetworkOnPrem)})

	risks, err := NewAuditLogManipulationRule().GenerateRisks(model)

	require.NoError(t, err)
	require.Len(t, risks, 1)
	assert.Equal(t, "audit-log-manipulation@log", risks[0].SyntheticId)
}

func TestAuditLogManipulationNoRiskForReadonlySameBoundaryOrOtherTechnology(t *testing.T) {
	build := func(tech string, readonly bool, appBoundary string) *types.Model {
		monitoring := ptAsset("log", ptTech(tech))
		app := ptAsset("app", ptTech(types.WebApplication))
		link := ptLink("l", "app", "log", types.HTTPS)
		link.Readonly = readonly
		return ptModel([]*types.TechnicalAsset{monitoring, app}, []*types.CommunicationLink{link},
			map[string]*types.TrustBoundary{"log": ptBoundary("tb1", types.NetworkOnPrem), "app": ptBoundary(appBoundary, types.NetworkOnPrem)})
	}
	for name, model := range map[string]*types.Model{
		"readonly":      build(types.Monitoring, true, "tb2"),
		"same boundary": build(types.Monitoring, false, "tb1"),
		"other tech":    build(types.Database, false, "tb2"),
	} {
		risks, err := NewAuditLogManipulationRule().GenerateRisks(model)
		assert.NoError(t, err, name)
		assert.Empty(t, risks, name)
	}
}
