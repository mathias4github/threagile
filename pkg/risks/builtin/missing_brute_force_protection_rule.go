package builtin

import (
	"github.com/threagile/threagile/pkg/types"
)

type MissingBruteForceProtectionRule struct{}

func NewMissingBruteForceProtectionRule() *MissingBruteForceProtectionRule {
	return &MissingBruteForceProtectionRule{}
}

func (*MissingBruteForceProtectionRule) Category() *types.RiskCategory {
	return &types.RiskCategory{
		ID:    "missing-brute-force-protection",
		Title: "Missing Brute-Force Protection",
		Description: "Logins with credentials (username and password) that are reachable from the internet or used by humans are a target for password guessing, " +
			"credential stuffing with leaked password lists and password spraying across many accounts.",
		Impact:     "If this risk is unmitigated, attackers might take over user accounts by trying passwords at high speed without being slowed down or detected.",
		ASVS:       "V2 - Authentication Verification Requirements",
		CheatSheet: "https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html",
		Action:     "Brute-Force Protection",
		Mitigation: "Apply rate limiting and progressive delays per account and per source, lock or step-up authentication after repeated failures, check new passwords " +
			"against breached password lists, alert on unusual login failure rates, and offer a second factor for sensitive accounts.",
		Check:          "Are failed logins rate limited per account and source and are breached passwords rejected?",
		Function:       types.Development,
		STRIDE:         types.Spoofing,
		DetectionLogic: "In-scope technical assets with incoming communication links authenticated by credentials from callers that are internet-facing or used by humans.",
		RiskAssessment: "The risk rating depends on the sensitivity of the technical asset itself and of the data assets processed; internet-facing callers raise the likelihood.",
		FalsePositives: "Logins protected by a central identity provider with built-in lockout and rate limiting, or technical accounts with random high-entropy " +
			"secrets, can be considered as false positives after individual review.",
		ModelFailurePossibleReason: false,
		CWE:                        307,
	}
}

func (*MissingBruteForceProtectionRule) SupportedTags() []string {
	return []string{}
}

func (r *MissingBruteForceProtectionRule) GenerateRisks(input *types.Model) ([]*types.Risk, error) {
	risks := make([]*types.Risk, 0)
	for _, id := range input.SortedTechnicalAssetIDs() {
		technicalAsset := input.TechnicalAssets[id]
		if technicalAsset.OutOfScope {
			continue
		}
		for _, incomingFlow := range sortedIncomingLinks(input, technicalAsset.Id) {
			source := input.TechnicalAssets[incomingFlow.SourceId]
			if source == nil || incomingFlow.Authentication != types.Credentials {
				continue
			}
			if !source.Internet && !source.UsedAsClientByHuman {
				continue
			}
			likelihood := types.Unlikely
			if source.Internet {
				likelihood = types.Likely
			}
			title := "<b>Missing Brute-Force Protection</b> covering communication link <b>" + incomingFlow.Title + "</b> from <b>" +
				source.Title + "</b> to <b>" + technicalAsset.Title + "</b>"
			risks = append(risks, newLinkRisk(r.Category().ID, title, likelihood, impactByCIA(input, technicalAsset),
				technicalAsset, incomingFlow, types.Possible))
		}
	}
	return risks, nil
}
