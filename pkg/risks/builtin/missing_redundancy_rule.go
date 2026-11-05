package builtin

import (
	"github.com/threagile/threagile/pkg/types"
)

type MissingRedundancyRule struct{}

func NewMissingRedundancyRule() *MissingRedundancyRule {
	return &MissingRedundancyRule{}
}

func (*MissingRedundancyRule) Category() *types.RiskCategory {
	return &types.RiskCategory{
		ID:    "missing-redundancy",
		Title: "Missing Redundancy (Single Point of Failure)",
		Description: "A technical asset whose availability is mission critical but which runs as a single instance fails completely on any outage, " +
			"whether caused by an attack, a defect or maintenance.",
		Impact: "If this risk is unmitigated, a single successful denial-of-service attack or a plain failure of the asset might stop the whole business process " +
			"depending on it.",
		ASVS:       "V1 - Architecture, Design and Threat Modeling Requirements",
		CheatSheet: "https://cheatsheetseries.owasp.org/cheatsheets/Denial_of_Service_Cheat_Sheet.html",
		Action:     "Redundancy",
		Mitigation: "Run mission critical assets redundantly (clustering, replication, multiple instances across failure domains), automate failover, and test " +
			"recovery regularly. Mark the asset as redundant in the model once this is in place.",
		Check:    "Does the asset survive the loss of a single instance or failure domain?",
		Function: types.Architecture,
		STRIDE:   types.DenialOfService,
		DetectionLogic: "In-scope non-client technical assets rated mission critical in availability (themselves or through the data assets processed) " +
			"that are not marked as redundant.",
		RiskAssessment: "The risk rating depends on the availability rating of the technical asset and of the data assets processed.",
		FalsePositives: "Assets that are redundant but not modeled as such, or whose outage is acceptable for the business, can be considered " +
			"as false positives after individual review.",
		ModelFailurePossibleReason: true,
		CWE:                        1008,
	}
}

func (*MissingRedundancyRule) SupportedTags() []string {
	return []string{}
}

func (r *MissingRedundancyRule) GenerateRisks(input *types.Model) ([]*types.Risk, error) {
	risks := make([]*types.Risk, 0)
	for _, id := range input.SortedTechnicalAssetIDs() {
		technicalAsset := input.TechnicalAssets[id]
		if technicalAsset.OutOfScope || technicalAsset.Redundant || technicalAsset.Technologies.GetAttribute(types.IsClient) {
			continue
		}
		if input.HighestProcessedAvailability(technicalAsset) != types.MissionCritical {
			continue
		}
		risks = append(risks, newAssetRisk(r.Category().ID,
			"<b>Missing Redundancy (Single Point of Failure)</b> risk at <b>"+technicalAsset.Title+"</b>",
			types.Unlikely, types.MediumImpact, technicalAsset, types.Improbable))
	}
	return risks, nil
}
