package builtin

import (
	"github.com/threagile/threagile/pkg/types"
)

type MissingMonitoringRule struct{}

func NewMissingMonitoringRule() *MissingMonitoringRule {
	return &MissingMonitoringRule{}
}

func (*MissingMonitoringRule) Category() *types.RiskCategory {
	return &types.RiskCategory{
		ID:    "missing-monitoring",
		Title: "Missing Security Monitoring",
		Description: "Architectures handling sensitive data should contain a component that collects security-relevant events (logins, failures, administrative " +
			"actions, anomalies) and makes attacks visible. Without it, breaches are detected late or by third parties.",
		Impact:     "If this risk is unmitigated, attacks and misuse might go unnoticed for a long time, increasing the damage and preventing a timely response.",
		ASVS:       "V7 - Error Handling and Logging Verification Requirements",
		CheatSheet: "https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html",
		Action:     "Security Monitoring",
		Mitigation: "Add a central logging and monitoring component (log management, SIEM, intrusion detection) that receives security events from the relevant " +
			"technical assets, define alerting rules and an incident response process, and protect the collected logs against modification.",
		Check:          "Is there a security monitoring component in place and do the sensitive assets send their security events to it?",
		Function:       types.Operations,
		STRIDE:         types.Repudiation,
		DetectionLogic: "Models containing in-scope technical assets processing sensitive data but no technical asset of technology monitoring, IDS or IPS.",
		RiskAssessment: "The risk rating depends on the sensitivity of the technical assets in the model.",
		FalsePositives: "Models of components whose monitoring is provided by a surrounding platform that is deliberately not part of the model can be " +
			"considered as false positives after individual review.",
		ModelFailurePossibleReason: true,
		CWE:                        778,
	}
}

func (*MissingMonitoringRule) SupportedTags() []string {
	return []string{}
}

func (r *MissingMonitoringRule) GenerateRisks(input *types.Model) ([]*types.Risk, error) {
	risks := make([]*types.Risk, 0)
	var mostRelevantAsset *types.TechnicalAsset
	for _, id := range input.SortedTechnicalAssetIDs() { // sorted: always the same example asset
		techAsset := input.TechnicalAssets[id]
		if techAsset.Technologies.GetAttribute(types.Monitoring, types.IDS, types.IPS) {
			return risks, nil
		}
		if techAsset.OutOfScope || !isSensitiveAsset(input, techAsset) {
			continue
		}
		if mostRelevantAsset == nil || processedSensitivityScore(input, techAsset) > processedSensitivityScore(input, mostRelevantAsset) {
			mostRelevantAsset = techAsset
		}
	}
	if mostRelevantAsset == nil {
		return risks, nil
	}
	impact := types.MediumImpact
	if input.HighestProcessedConfidentiality(mostRelevantAsset) == types.StrictlyConfidential ||
		input.HighestProcessedIntegrity(mostRelevantAsset) == types.MissionCritical {
		impact = types.HighImpact
	}
	risk := newAssetRisk(r.Category().ID,
		"<b>Missing Security Monitoring</b> in the threat model (referencing asset <b>"+mostRelevantAsset.Title+"</b> as an example)",
		types.Unlikely, impact, mostRelevantAsset, types.Improbable)
	risk.DataBreachTechnicalAssetIDs = []string{}
	risks = append(risks, risk)
	return risks, nil
}
