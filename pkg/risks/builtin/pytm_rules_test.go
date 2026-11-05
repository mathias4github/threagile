package builtin

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/threagile/threagile/pkg/types"
)

func TestPytmRulesEmptyModelCreatesNoRisks(t *testing.T) {
	rules := []types.RiskRule{
		NewHttpRequestSmugglingRule(), NewMailCommandInjectionRule(), NewMissingClickjackingProtectionRule(),
		NewSharedDatastoreTamperingRule(), NewXmlEntityExpansionDosRule(), NewLlmPromptInjectionRule(),
		NewAiSensitiveDataExposureRule(), NewClientReverseEngineeringRule(), NewAuditLogManipulationRule(),
		NewXmlSchemaPoisoningRule(),
	}
	for _, rule := range rules {
		risks, err := rule.GenerateRisks(&types.Model{})
		assert.NoError(t, err, rule.Category().ID)
		assert.Empty(t, risks, rule.Category().ID)
	}
}

// A caller inside an execution-environment boundary that is nested in the same network
// as the target is not "across a trust boundary" (same semantics as the existing rules).
func TestPytmRulesNestedBoundaryInSameNetworkIsNotAcross(t *testing.T) {
	network := ptBoundary("net", types.NetworkOnPrem)
	runtime := ptBoundary("rt", types.ExecutionEnvironment)

	xmlTarget := ptAsset("svc", ptTech(types.WebApplication))
	xmlTarget.DataFormatsAccepted = []types.DataFormat{types.XML}
	monitoring := ptAsset("log", ptTech(types.Monitoring))
	llm := ptAsset("llm", ptTech(types.AI))
	store := ptAsset("db", ptTech(types.Database))
	store.Type = types.Datastore
	callerA := ptAsset("a", ptTech(types.WebApplication))
	callerB := ptAsset("b", ptTech(types.WebApplication))

	model := ptModel(
		[]*types.TechnicalAsset{xmlTarget, monitoring, llm, store, callerA, callerB},
		[]*types.CommunicationLink{
			ptLink("l1", "a", "svc", types.HTTPS), ptLink("l2", "a", "log", types.HTTPS), ptLink("l3", "a", "llm", types.HTTPS),
			ptLink("l4", "a", "db", types.JdbcEncrypted), ptLink("l5", "b", "db", types.JdbcEncrypted),
		},
		map[string]*types.TrustBoundary{"svc": network, "log": network, "llm": network, "db": network, "b": network, "a": runtime})
	ptNest(model, network, runtime)

	for _, rule := range []types.RiskRule{NewXmlEntityExpansionDosRule(), NewAuditLogManipulationRule(), NewLlmPromptInjectionRule(), NewSharedDatastoreTamperingRule()} {
		risks, err := rule.GenerateRisks(model)
		assert.NoError(t, err, rule.Category().ID)
		assert.Empty(t, risks, rule.Category().ID)
	}
}
