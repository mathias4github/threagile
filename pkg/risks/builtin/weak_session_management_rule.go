package builtin

import (
	"github.com/threagile/threagile/pkg/types"
)

type WeakSessionManagementRule struct{}

func NewWeakSessionManagementRule() *WeakSessionManagementRule {
	return &WeakSessionManagementRule{}
}

func (*WeakSessionManagementRule) Category() *types.RiskCategory {
	return &types.RiskCategory{
		ID:    "weak-session-management",
		Title: "Weak Session Management",
		Description: "Web assets that keep user sessions in tokens or cookies are exposed to session fixation, prediction, replay and hijacking when identifiers are " +
			"guessable, long-lived, not bound to the transport or not invalidated on logout.",
		Impact:     "If this risk is unmitigated, attackers might take over authenticated sessions of users without knowing their credentials.",
		ASVS:       "V3 - Session Management Verification Requirements",
		CheatSheet: "https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html",
		Action:     "Session Hardening",
		Mitigation: "Generate session identifiers with a cryptographically secure random generator, rotate them on login and privilege change, set Secure, HttpOnly " +
			"and SameSite on cookies, enforce idle and absolute timeouts, invalidate sessions server-side on logout, and bind tokens to the TLS session where possible.",
		Check:          "Are session identifiers random, rotated on login, transported only over TLS and invalidated on logout and timeout?",
		Function:       types.Development,
		STRIDE:         types.Spoofing,
		DetectionLogic: "In-scope technical assets tagged with session-tokens that are accessed via web protocols by in-scope clients used by humans.",
		RiskAssessment: "The risk rating depends on the sensitivity of the technical asset itself and of the data assets processed.",
		FalsePositives: "Assets whose session handling is fully provided by a hardened framework or identity provider with the settings above can be considered " +
			"as false positives after individual review.",
		ModelFailurePossibleReason: false,
		CWE:                        613,
	}
}

func (*WeakSessionManagementRule) SupportedTags() []string {
	return []string{"session-tokens"}
}

func (r *WeakSessionManagementRule) GenerateRisks(input *types.Model) ([]*types.Risk, error) {
	risks := make([]*types.Risk, 0)
	for _, id := range input.SortedTechnicalAssetIDs() {
		technicalAsset := input.TechnicalAssets[id]
		if technicalAsset.OutOfScope || !technicalAsset.IsTaggedWithAny(r.SupportedTags()...) {
			continue
		}
		for _, incomingFlow := range sortedIncomingLinks(input, technicalAsset.Id) {
			source := input.TechnicalAssets[incomingFlow.SourceId]
			if source == nil || source.OutOfScope || !source.UsedAsClientByHuman || !incomingFlow.Protocol.IsPotentialWebAccessProtocol() {
				continue
			}
			risks = append(risks, newAssetRisk(r.Category().ID,
				"<b>Weak Session Management</b> risk at <b>"+technicalAsset.Title+"</b>",
				types.Likely, impactByCIA(input, technicalAsset), technicalAsset, types.Possible))
			break
		}
	}
	return risks, nil
}
