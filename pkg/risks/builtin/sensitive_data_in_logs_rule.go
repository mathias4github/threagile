package builtin

import (
	"github.com/threagile/threagile/pkg/types"
)

type SensitiveDataInLogsRule struct{}

func NewSensitiveDataInLogsRule() *SensitiveDataInLogsRule {
	return &SensitiveDataInLogsRule{}
}

func (*SensitiveDataInLogsRule) Category() *types.RiskCategory {
	return &types.RiskCategory{
		ID:    "sensitive-data-in-logs",
		Title: "Sensitive Data in Logs",
		Description: "Monitoring and logging components that receive confidential data (credentials, tokens, personal or business secrets) store it with weaker " +
			"protection and wider access than the systems of origin, often for a long retention period.",
		Impact: "If this risk is unmitigated, confidential data might be exposed to everyone with access to the logs, to log forwarding services, or through backups " +
			"of the log store.",
		ASVS:       "V7 - Error Handling and Logging Verification Requirements",
		CheatSheet: "https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html",
		Action:     "Log Data Minimization",
		Mitigation: "Do not log credentials, tokens, session identifiers or payloads containing confidential data; mask or pseudonymize personal data before it is " +
			"written, restrict access to the log store, encrypt it at rest and define a short retention period.",
		Check:                      "Are confidential values excluded or masked before logging and is access to the logs restricted?",
		Function:                   types.Development,
		STRIDE:                     types.InformationDisclosure,
		DetectionLogic:             "In-scope monitoring technical assets processing data assets rated confidential or higher.",
		RiskAssessment:             "The risk rating depends on the confidentiality rating of the data assets processed by the monitoring asset.",
		FalsePositives:             "Monitoring assets that only receive masked or aggregated data can be considered as false positives after individual review.",
		ModelFailurePossibleReason: false,
		CWE:                        532,
	}
}

func (*SensitiveDataInLogsRule) SupportedTags() []string {
	return []string{}
}

func (r *SensitiveDataInLogsRule) GenerateRisks(input *types.Model) ([]*types.Risk, error) {
	risks := make([]*types.Risk, 0)
	for _, id := range input.SortedTechnicalAssetIDs() {
		technicalAsset := input.TechnicalAssets[id]
		if technicalAsset.OutOfScope || !technicalAsset.Technologies.GetAttribute(types.Monitoring) {
			continue
		}
		confidentiality := input.HighestProcessedConfidentiality(technicalAsset)
		if confidentiality < types.Confidential {
			continue
		}
		impact := types.MediumImpact
		probability := types.Possible
		if confidentiality == types.StrictlyConfidential {
			impact = types.HighImpact
			probability = types.Probable
		}
		risks = append(risks, newAssetRisk(r.Category().ID,
			"<b>Sensitive Data in Logs</b> risk at <b>"+technicalAsset.Title+"</b>",
			types.Unlikely, impact, technicalAsset, probability))
	}
	return risks, nil
}
