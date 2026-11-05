package builtin

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/threagile/threagile/pkg/types"
)

func TestAiSensitiveDataExposureCloudBoundaryCreatesRisk(t *testing.T) {
	llm := ptAsset("llm", ptTech(types.AI))
	model := ptModel([]*types.TechnicalAsset{llm}, nil, map[string]*types.TrustBoundary{"llm": ptBoundary("cloud", types.NetworkCloudProvider)})
	ptProcess(model, llm, types.StrictlyConfidential, types.Operational)

	risks, err := NewAiSensitiveDataExposureRule().GenerateRisks(model)

	require.NoError(t, err)
	require.Len(t, risks, 1)
	assert.Equal(t, types.HighImpact, risks[0].ExploitationImpact)
}

func TestAiSensitiveDataExposureOutgoingLinkToInternetAssetCreatesRisk(t *testing.T) {
	llm := ptAsset("llm", ptTech(types.AI))
	site := ptAsset("site", ptTech(types.WebServer))
	site.Internet = true
	model := ptModel([]*types.TechnicalAsset{llm, site}, []*types.CommunicationLink{ptLink("l", "llm", "site", types.HTTPS)}, nil)
	ptProcess(model, llm, types.Confidential, types.Operational)

	risks, err := NewAiSensitiveDataExposureRule().GenerateRisks(model)

	require.NoError(t, err)
	require.Len(t, risks, 1)
	assert.Equal(t, types.MediumImpact, risks[0].ExploitationImpact)
}

func TestAiSensitiveDataExposureNoRiskForPublicDataOrOnPremIsolation(t *testing.T) {
	llm := ptAsset("llm", ptTech(types.AI))
	model := ptModel([]*types.TechnicalAsset{llm}, nil, map[string]*types.TrustBoundary{"llm": ptBoundary("cloud", types.NetworkCloudProvider)})
	ptProcess(model, llm, types.Internal, types.Operational)
	risks, _ := NewAiSensitiveDataExposureRule().GenerateRisks(model)
	assert.Empty(t, risks, "data not confidential")

	llm2 := ptAsset("llm", ptTech(types.AI))
	model2 := ptModel([]*types.TechnicalAsset{llm2}, nil, map[string]*types.TrustBoundary{"llm": ptBoundary("prem", types.NetworkOnPrem)})
	ptProcess(model2, llm2, types.StrictlyConfidential, types.Operational)
	risks, _ = NewAiSensitiveDataExposureRule().GenerateRisks(model2)
	assert.Empty(t, risks, "on-prem without less protected recipients")
}
