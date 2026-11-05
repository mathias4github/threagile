package builtin

import (
	"github.com/threagile/threagile/pkg/types"
)

type LlmExcessiveAgencyRule struct{}

func NewLlmExcessiveAgencyRule() *LlmExcessiveAgencyRule {
	return &LlmExcessiveAgencyRule{}
}

func (*LlmExcessiveAgencyRule) Category() *types.RiskCategory {
	return &types.RiskCategory{
		ID:    "llm-excessive-agency",
		Title: "Excessive Agency of AI Component",
		Description: "AI components that act as agents (calling tools, changing data in other systems or executing code) turn every successful prompt injection " +
			"or model error into a real-world action. The broader their permissions and reach, the larger the damage.",
		Impact: "If this risk is unmitigated, a manipulated or malfunctioning AI component might modify critical data, trigger business transactions or " +
			"execute code in other systems without human control.",
		ASVS:       "V4 - Access Control Verification Requirements",
		CheatSheet: "https://cheatsheetseries.owasp.org/cheatsheets/LLM_Prompt_Injection_Prevention_Cheat_Sheet.html",
		Action:     "Least Privilege for AI Agents",
		Mitigation: "Give the AI component only the tools and permissions it needs, use read-only or scoped credentials towards other systems, require human approval " +
			"for state-changing or high-impact actions, run code execution in an isolated sandbox, and log and rate limit all agent actions.",
		Check:    "Are the agent's tools and permissions minimal, is code execution sandboxed, and do high-impact actions require approval?",
		Function: types.Architecture,
		STRIDE:   types.ElevationOfPrivilege,
		DetectionLogic: "In-scope AI technical assets tagged with executes-code, or tagged with ai-agent and having outgoing communication links to in-scope " +
			"technical assets rated critical or higher in integrity.",
		RiskAssessment:             "The risk rating depends on the integrity rating of the reachable technical assets; code execution raises the impact.",
		FalsePositives:             "Agents restricted to read-only tools with approval for every state-changing action can be considered as false positives after individual review.",
		ModelFailurePossibleReason: false,
		CWE:                        250,
	}
}

func (*LlmExcessiveAgencyRule) SupportedTags() []string {
	return []string{"ai-agent", "executes-code"}
}

func (r *LlmExcessiveAgencyRule) GenerateRisks(input *types.Model) ([]*types.Risk, error) {
	risks := make([]*types.Risk, 0)
	for _, id := range input.SortedTechnicalAssetIDs() {
		technicalAsset := input.TechnicalAssets[id]
		if technicalAsset.OutOfScope || !technicalAsset.Technologies.GetAttribute(types.AI) || !technicalAsset.IsTaggedWithAny(r.SupportedTags()...) {
			continue
		}
		executesCode := technicalAsset.IsTaggedWithAny("executes-code")
		reachesCritical := false
		for _, link := range technicalAsset.CommunicationLinks {
			target := input.TechnicalAssets[link.TargetId]
			if target != nil && !target.OutOfScope && input.HighestProcessedIntegrity(target) >= types.Critical {
				reachesCritical = true
			}
		}
		if !executesCode && !reachesCritical {
			continue
		}
		impact := types.MediumImpact
		if executesCode {
			impact = types.HighImpact
		}
		risks = append(risks, newAssetRisk(r.Category().ID,
			"<b>Excessive Agency of AI Component</b> risk at <b>"+technicalAsset.Title+"</b>",
			types.Likely, impact, technicalAsset, types.Possible))
	}
	return risks, nil
}
