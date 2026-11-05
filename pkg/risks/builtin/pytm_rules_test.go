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
