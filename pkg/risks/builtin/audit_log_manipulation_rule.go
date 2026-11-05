package builtin

import (
	"github.com/threagile/threagile/pkg/types"
)

type AuditLogManipulationRule struct{}

func NewAuditLogManipulationRule() *AuditLogManipulationRule {
	return &AuditLogManipulationRule{}
}

func (*AuditLogManipulationRule) Category() *types.RiskCategory {
	return &types.RiskCategory{
		ID:    "audit-log-manipulation",
		Title: "Audit Log Manipulation",
		Description: "Monitoring and logging components that accept data from sources in other trust boundaries can be fed with forged or injected entries. " +
			"A compromised source can also flood the component or hide its own traces.",
		Impact:     "If this risk is unmitigated, attackers might forge, suppress or inject log entries and thereby cover their tracks or mislead incident response.",
		ASVS:       "V7 - Error Handling and Logging Verification Requirements",
		CheatSheet: "https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html",
		Action:     "Log Integrity Protection",
		Mitigation: "Accept log data only through authenticated channels with append-only permissions, neutralize control characters in logged values, add integrity " +
			"protection (signatures or hash chains) and ship logs promptly to a store the producers cannot modify.",
		Check:                      "Is log ingestion authenticated and append-only and are log entries protected against modification?",
		Function:                   types.Operations,
		STRIDE:                     types.Repudiation,
		DetectionLogic:             "In-scope monitoring technical assets with write access from in-scope technical assets located in another network trust boundary.",
		RiskAssessment:             "The risk rating depends on the integrity rating of the monitoring asset and of the data assets processed.",
		FalsePositives:             "Log pipelines with authenticated, append-only ingestion and integrity protection can be considered as false positives after individual review.",
		ModelFailurePossibleReason: false,
		CWE:                        117,
	}
}

func (*AuditLogManipulationRule) SupportedTags() []string {
	return []string{}
}

func (r *AuditLogManipulationRule) GenerateRisks(input *types.Model) ([]*types.Risk, error) {
	risks := make([]*types.Risk, 0)
	for _, id := range input.SortedTechnicalAssetIDs() {
		technicalAsset := input.TechnicalAssets[id]
		if technicalAsset.OutOfScope || !technicalAsset.Technologies.GetAttribute(types.Monitoring) {
			continue
		}
		for _, incomingFlow := range input.IncomingTechnicalCommunicationLinksMappedByTargetId[technicalAsset.Id] {
			source := input.TechnicalAssets[incomingFlow.SourceId]
			if source == nil || source.OutOfScope || incomingFlow.Readonly || !isAcrossTrustBoundaryNetworkOnly(input, incomingFlow) {
				continue
			}
			impact := types.LowImpact
			if input.HighestProcessedIntegrity(technicalAsset) >= types.Critical {
				impact = types.MediumImpact
			}
			risks = append(risks, newAssetRisk(r.Category().ID,
				"<b>Audit Log Manipulation</b> risk at <b>"+technicalAsset.Title+"</b>",
				types.Unlikely, impact, technicalAsset, types.Improbable))
			break
		}
	}
	return risks, nil
}
