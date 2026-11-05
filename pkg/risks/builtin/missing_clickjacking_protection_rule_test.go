package builtin

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/threagile/threagile/pkg/types"
)

func TestMissingClickjackingProtectionHumanClientCreatesRisk(t *testing.T) {
	browser := ptAsset("browser", ptTech(types.Browser))
	browser.UsedAsClientByHuman = true
	web := ptAsset("web", ptTech(types.WebApplication))
	model := ptModel([]*types.TechnicalAsset{browser, web}, []*types.CommunicationLink{ptLink("l", "browser", "web", types.HTTPS)}, nil)

	risks, err := NewMissingClickjackingProtectionRule().GenerateRisks(model)

	require.NoError(t, err)
	require.Len(t, risks, 1)
	assert.Equal(t, "missing-clickjacking-protection@web", risks[0].SyntheticId)
}

func TestMissingClickjackingProtectionNoRiskWithoutHumanClient(t *testing.T) {
	service := ptAsset("service", ptTech(types.WebServiceREST))
	web := ptAsset("web", ptTech(types.WebApplication))
	model := ptModel([]*types.TechnicalAsset{service, web}, []*types.CommunicationLink{ptLink("l", "service", "web", types.HTTPS)}, nil)

	risks, err := NewMissingClickjackingProtectionRule().GenerateRisks(model)

	require.NoError(t, err)
	assert.Empty(t, risks)
}
