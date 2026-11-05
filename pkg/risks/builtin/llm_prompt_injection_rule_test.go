package builtin

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/threagile/threagile/pkg/types"
)


func TestLlmPromptInjectionHumanClientCreatesLikelyRisk(t *testing.T) {
	user := ptAsset("user", ptTech(types.Browser))
	user.UsedAsClientByHuman = true
	llm := ptAsset("llm", ptTech(types.AI))

	risks, err := NewLlmPromptInjectionRule().GenerateRisks(ptModel([]*types.TechnicalAsset{user, llm}, []*types.CommunicationLink{ptLink("l", "user", "llm", types.HTTPS)}, nil))

	require.NoError(t, err)
	require.Len(t, risks, 1)
	assert.Equal(t, "llm-prompt-injection@llm", risks[0].SyntheticId)
	assert.Equal(t, types.Likely, risks[0].ExploitationLikelihood)
}

func TestLlmPromptInjectionSameBoundaryTrustedSourceNoRisk(t *testing.T) {
	backend := ptAsset("backend", ptTech(types.WebApplication))
	llm := ptAsset("llm", ptTech(types.AI))
	tb := ptBoundary("tb", types.NetworkOnPrem)
	model := ptModel([]*types.TechnicalAsset{backend, llm}, []*types.CommunicationLink{ptLink("l", "backend", "llm", types.HTTPS)},
		map[string]*types.TrustBoundary{"backend": tb, "llm": tb})

	risks, err := NewLlmPromptInjectionRule().GenerateRisks(model)

	require.NoError(t, err)
	assert.Empty(t, risks)
}

func TestLlmPromptInjectionOtherBoundaryCreatesUnlikelyRiskAndNonAiIsIgnored(t *testing.T) {
	backend := ptAsset("backend", ptTech(types.WebApplication))
	llm := ptAsset("llm", ptTech(types.AI))
	notAi := ptAsset("plain", ptTech(types.WebApplication))
	boundaries := map[string]*types.TrustBoundary{"backend": ptBoundary("tb1", types.NetworkOnPrem), "llm": ptBoundary("tb2", types.NetworkOnPrem), "plain": ptBoundary("tb2", types.NetworkOnPrem)}
	model := ptModel([]*types.TechnicalAsset{backend, llm, notAi},
		[]*types.CommunicationLink{ptLink("l", "backend", "llm", types.HTTPS), ptLink("l2", "backend", "plain", types.HTTPS)}, boundaries)

	risks, err := NewLlmPromptInjectionRule().GenerateRisks(model)

	require.NoError(t, err)
	require.Len(t, risks, 1)
	assert.Equal(t, types.Unlikely, risks[0].ExploitationLikelihood)
}
