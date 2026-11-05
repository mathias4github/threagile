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

func TestAiSensitiveDataExposureOwnInternetFacingTargetIsNoRecipient(t *testing.T) {
	llm := ptAsset("llm", ptTech(types.AI))
	site := ptAsset("site", ptTech(types.WebServer))
	site.Internet = true
	model := ptModel([]*types.TechnicalAsset{llm, site}, []*types.CommunicationLink{ptLink("l", "llm", "site", types.HTTPS)}, nil)
	ptProcess(model, llm, types.StrictlyConfidential, types.Operational)

	risks, err := NewAiSensitiveDataExposureRule().GenerateRisks(model)

	require.NoError(t, err)
	assert.Empty(t, risks)
}

func TestAiSensitiveDataExposureThirdPartyProviderAndHumanConsumerCreateRisk(t *testing.T) {
	llm := ptAsset("llm", ptTech(types.AI))
	provider := ptAsset("provider", ptTech(types.AI))
	provider.OutOfScope = true
	model := ptModel([]*types.TechnicalAsset{llm, provider}, []*types.CommunicationLink{ptLink("l", "llm", "provider", types.HTTPS)}, nil)
	ptProcess(model, llm, types.Confidential, types.Operational)
	risks, err := NewAiSensitiveDataExposureRule().GenerateRisks(model)
	require.NoError(t, err)
	assert.Len(t, risks, 1, "out-of-scope provider")

	llm2 := ptAsset("llm", ptTech(types.AI))
	user := ptAsset("user", ptTech(types.Browser))
	user.UsedAsClientByHuman = true
	model2 := ptModel([]*types.TechnicalAsset{llm2, user}, []*types.CommunicationLink{ptLink("l", "user", "llm", types.HTTPS)}, nil)
	ptProcess(model2, llm2, types.Confidential, types.Operational)
	risks, err = NewAiSensitiveDataExposureRule().GenerateRisks(model2)
	require.NoError(t, err)
	assert.Len(t, risks, 1, "human consumer of generated output")
}
