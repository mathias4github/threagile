package builtin

import (
	"github.com/threagile/threagile/pkg/types"
)

type LlmPromptInjectionRule struct{}

func NewLlmPromptInjectionRule() *LlmPromptInjectionRule {
	return &LlmPromptInjectionRule{}
}

func (*LlmPromptInjectionRule) Category() *types.RiskCategory {
	return &types.RiskCategory{
		ID:    "llm-prompt-injection",
		Title: "Prompt Injection and Jailbreaking",
		Description: "AI components that process text from users or from other trust boundaries cannot reliably tell instructions from data. " +
			"Crafted input can override the intended behavior, circumvent safety rules, or make the component reveal its configuration.",
		Impact: "If this risk is unmitigated, attackers might be able to make the AI component produce harmful output, disclose confidential instructions or data, " +
			"or trigger actions it was not meant to perform.",
		ASVS:       "V1 - Architecture, Design and Threat Modeling Requirements",
		CheatSheet: "https://cheatsheetseries.owasp.org/cheatsheets/LLM_Prompt_Injection_Prevention_Cheat_Sheet.html",
		Action:     "Prompt Injection Defense",
		Mitigation: "Treat all model input and output as untrusted. Separate instructions from user data, filter input and output, restrict the capabilities and " +
			"data the component can reach to the minimum, require human approval for sensitive actions, and test regularly with adversarial prompts.",
		Check:          "Are input and output filtered and is the AI component limited to the minimum of capabilities and data?",
		Function:       types.Development,
		STRIDE:         types.Tampering,
		DetectionLogic: "In-scope AI technical assets receiving input from internet-facing assets, human-operated clients or assets in other network trust boundaries.",
		RiskAssessment: "The risk rating depends on the sensitivity of the AI asset itself and of the data assets processed; direct access by humans or from the " +
			"internet raises the likelihood.",
		FalsePositives: "AI components only fed by fully trusted, fixed input without any influence of users or external content can be considered " +
			"as false positives after individual review.",
		ModelFailurePossibleReason: false,
		CWE:                        1427,
	}
}

func (*LlmPromptInjectionRule) SupportedTags() []string {
	return []string{}
}

func (r *LlmPromptInjectionRule) GenerateRisks(input *types.Model) ([]*types.Risk, error) {
	risks := make([]*types.Risk, 0)
	for _, id := range input.SortedTechnicalAssetIDs() {
		technicalAsset := input.TechnicalAssets[id]
		if technicalAsset.OutOfScope || !technicalAsset.Technologies.GetAttribute(types.AI) {
			continue
		}
		found := false
		likelihood := types.Unlikely
		for _, incomingFlow := range input.IncomingTechnicalCommunicationLinksMappedByTargetId[technicalAsset.Id] {
			source := input.TechnicalAssets[incomingFlow.SourceId]
			if source == nil {
				continue
			}
			direct := source.Internet || source.UsedAsClientByHuman
			if direct || isAcrossTrustBoundaryNetworkOnly(input, incomingFlow) {
				found = true
			}
			if direct {
				likelihood = types.Likely
			}
		}
		if !found {
			continue
		}
		risks = append(risks, newAssetRisk(r.Category().ID,
			"<b>Prompt Injection and Jailbreaking</b> risk at <b>"+technicalAsset.Title+"</b>",
			likelihood, impactByCIA(input, technicalAsset), technicalAsset, types.Possible))
	}
	return risks, nil
}
