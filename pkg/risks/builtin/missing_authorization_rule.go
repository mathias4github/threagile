package builtin

import (
	"github.com/threagile/threagile/pkg/types"
)

type MissingAuthorizationRule struct{}

func NewMissingAuthorizationRule() *MissingAuthorizationRule {
	return &MissingAuthorizationRule{}
}

func (*MissingAuthorizationRule) Category() *types.RiskCategory {
	return &types.RiskCategory{
		ID:    "missing-authorization",
		Title: "Missing Authorization",
		Description: "A communication link that authenticates the caller but does not authorize the request gives every authenticated caller the same rights. " +
			"For datastores, queues and internal services this means that any compromised or misbehaving client can read or change all data.",
		Impact: "If this risk is unmitigated, attackers controlling one authenticated caller might access or modify data and functions far beyond what " +
			"that caller needs.",
		ASVS:       "V4 - Access Control Verification Requirements",
		CheatSheet: "https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html",
		Action:     "Authorization of Technical Access",
		Mitigation: "Define per caller which operations and data are permitted (least privilege) and enforce it at the target: separate database accounts, schemas or " +
			"roles, queue-level permissions, scoped tokens or service-mesh policies. Prefer end user identity propagation where requests originate from end users.",
		Check:    "Is each authenticated caller restricted to the operations and data it needs?",
		Function: types.Architecture,
		STRIDE:   types.ElevationOfPrivilege,
		DetectionLogic: "In-scope technical assets processing sensitive data that do not usually process end user requests (datastores, queues, internal services) " +
			"with incoming authenticated communication links without any authorization from in-scope callers. End user facing assets are covered by the " +
			"missing identity propagation rule.",
		RiskAssessment: "The risk rating depends on the sensitivity of the technical asset itself and of the data assets processed.",
		FalsePositives: "Callers that legitimately need full access to the target (for example a single owning application of a datastore) can be considered " +
			"as false positives after individual review.",
		ModelFailurePossibleReason: false,
		CWE:                        862,
	}
}

func (*MissingAuthorizationRule) SupportedTags() []string {
	return []string{}
}

func (r *MissingAuthorizationRule) GenerateRisks(input *types.Model) ([]*types.Risk, error) {
	risks := make([]*types.Risk, 0)
	for _, id := range input.SortedTechnicalAssetIDs() {
		technicalAsset := input.TechnicalAssets[id]
		if technicalAsset.OutOfScope || technicalAsset.Technologies.GetAttribute(types.IsUsuallyProcessingEndUserRequests) {
			continue
		}
		if !isSensitiveAsset(input, technicalAsset) {
			continue
		}
		for _, incomingFlow := range sortedIncomingLinks(input, technicalAsset.Id) {
			source := input.TechnicalAssets[incomingFlow.SourceId]
			if source == nil || source.OutOfScope {
				continue
			}
			if incomingFlow.Authentication == types.NoneAuthentication || incomingFlow.Authorization != types.NoneAuthorization {
				continue
			}
			title := "<b>Missing Authorization</b> covering communication link <b>" + incomingFlow.Title + "</b> from <b>" +
				source.Title + "</b> to <b>" + technicalAsset.Title + "</b>"
			risks = append(risks, newLinkRisk(r.Category().ID, title, types.Unlikely, impactByCIA(input, technicalAsset),
				technicalAsset, incomingFlow, types.Possible))
		}
	}
	return risks, nil
}
