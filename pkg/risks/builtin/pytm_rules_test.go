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

// Out-of-scope callers (browsers, external clients, foreign proxies) are the attack path and must not
// suppress risks of the in-scope target. Only mail-command-injection keeps skipping them, because there
// the vulnerable code is in the caller (like ldap-injection).
func TestPytmRulesOutOfScopeCallerStillCreatesRisk(t *testing.T) {
	client := ptAsset("client", ptTech(types.Browser))
	client.Internet, client.UsedAsClientByHuman, client.OutOfScope = true, true, true
	proxy := ptAsset("proxy", ptTech(types.ReverseProxy, types.IsTrafficForwarding))
	proxy.OutOfScope = true
	web := ptAsset("web", ptTech(types.WebApplication))
	web.DataFormatsAccepted = []types.DataFormat{types.XML}
	llm := ptAsset("llm", ptTech(types.AI))
	xmlLink := ptLink("l1", "client", "web", types.HTTPS)
	xmlLink.Authorization = types.NoneAuthorization
	proxyLink := ptLink("l2", "proxy", "web", types.HTTPS)
	proxyLink.Authorization = types.TechnicalUser // only the client link is unauthorized
	model := ptModel([]*types.TechnicalAsset{client, proxy, web, llm},
		[]*types.CommunicationLink{xmlLink, proxyLink, ptLink("l3", "client", "llm", types.HTTPS)}, nil)

	for _, rule := range []types.RiskRule{NewMissingClickjackingProtectionRule(), NewHttpRequestSmugglingRule(), NewXmlSchemaPoisoningRule(), NewLlmPromptInjectionRule()} {
		risks, err := rule.GenerateRisks(model)
		assert.NoError(t, err, rule.Category().ID)
		assert.Len(t, risks, 1, rule.Category().ID)
	}
}
