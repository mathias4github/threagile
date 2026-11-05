package builtin

import (
	"github.com/threagile/threagile/pkg/types"
)

type MissingClickjackingProtectionRule struct{}

func NewMissingClickjackingProtectionRule() *MissingClickjackingProtectionRule {
	return &MissingClickjackingProtectionRule{}
}

func (*MissingClickjackingProtectionRule) Category() *types.RiskCategory {
	return &types.RiskCategory{
		ID:    "missing-clickjacking-protection",
		Title: "Missing Clickjacking Protection",
		Description: "Web applications used by humans in a browser can be embedded invisibly into pages of an attacker (frames) so that users are tricked " +
			"into clicking on elements of the application without noticing.",
		Impact:     "If this risk is unmitigated, attackers might trick authenticated users into performing unintended actions in the application.",
		ASVS:       "V14 - Configuration Verification Requirements",
		CheatSheet: "https://cheatsheetseries.owasp.org/cheatsheets/Clickjacking_Defense_Cheat_Sheet.html",
		Action:     "Anti-Framing Headers",
		Mitigation: "Forbid embedding of the application into foreign pages by sending a Content-Security-Policy header with a restrictive frame-ancestors " +
			"directive (and optionally X-Frame-Options). Additionally use SameSite cookies and re-authentication for critical actions.",
		Check:          "Do all responses carry a restrictive frame-ancestors policy?",
		Function:       types.Development,
		STRIDE:         types.Spoofing,
		DetectionLogic: "In-scope web applications accessed via web protocols by clients used by humans (in scope or not).",
		RiskAssessment: "The risk rating depends on the sensitivity of the web application itself and of the data assets processed.",
		FalsePositives: "Applications that already send a restrictive frame policy for all responses, or that offer no state-changing or sensitive functionality, " +
			"can be considered as false positives after individual review.",
		ModelFailurePossibleReason: false,
		CWE:                        1021,
	}
}

func (*MissingClickjackingProtectionRule) SupportedTags() []string {
	return []string{}
}

func (r *MissingClickjackingProtectionRule) GenerateRisks(input *types.Model) ([]*types.Risk, error) {
	risks := make([]*types.Risk, 0)
	for _, id := range input.SortedTechnicalAssetIDs() {
		technicalAsset := input.TechnicalAssets[id]
		if technicalAsset.OutOfScope {
			continue
		}
		if !technicalAsset.Technologies.GetAttribute(types.WebApplication, isWebApplicationAttribute) {
			continue
		}
		for _, incomingFlow := range input.IncomingTechnicalCommunicationLinksMappedByTargetId[technicalAsset.Id] {
			source := input.TechnicalAssets[incomingFlow.SourceId]
			if source == nil || !source.UsedAsClientByHuman {
				continue
			}
			if !incomingFlow.Protocol.IsPotentialWebAccessProtocol() {
				continue
			}
			risks = append(risks, newAssetRisk(r.Category().ID,
				"<b>Missing Clickjacking Protection</b> risk at <b>"+technicalAsset.Title+"</b>",
				types.Unlikely, impactByCIA(input, technicalAsset), technicalAsset, types.Improbable))
			break
		}
	}
	return risks, nil
}
