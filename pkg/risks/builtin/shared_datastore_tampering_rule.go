package builtin

import (
	"github.com/threagile/threagile/pkg/types"
)

type SharedDatastoreTamperingRule struct{}

func NewSharedDatastoreTamperingRule() *SharedDatastoreTamperingRule {
	return &SharedDatastoreTamperingRule{}
}

func (*SharedDatastoreTamperingRule) Category() *types.RiskCategory {
	return &types.RiskCategory{
		ID:    "shared-datastore-tampering",
		Title: "Shared Datastore Tampering",
		Description: "A datastore that is written to by components from several trust boundaries can be manipulated by the least protected of its writers, " +
			"and the other users of the data then rely on tampered content.",
		Impact: "If this risk is unmitigated, an attacker compromising one writing component might alter data that other components in better protected " +
			"areas trust and process further.",
		ASVS:       "V1 - Architecture, Design and Threat Modeling Requirements",
		CheatSheet: "https://cheatsheetseries.owasp.org/cheatsheets/Threat_Modeling_Cheat_Sheet.html",
		Action:     "Data Ownership and Write Separation",
		Mitigation: "Give each writing component its own schema, collection or datastore and only read-only access to the data of others. Validate data read from " +
			"shared stores as if it were untrusted input, and use integrity protection for security-relevant records.",
		Check:          "Is write access to the datastore separated per trust boundary and is data read from it validated?",
		Function:       types.Architecture,
		STRIDE:         types.Tampering,
		DetectionLogic: "In-scope datastores with write access from technical assets located in at least two different network trust boundaries.",
		RiskAssessment: "The risk rating depends on the integrity rating of the datastore and of the data assets processed.",
		FalsePositives: "Datastores with strictly partitioned write permissions per writer (separate schemas or accounts) can be considered as false positives " +
			"after individual review.",
		ModelFailurePossibleReason: false,
		CWE:                        345,
	}
}

func (*SharedDatastoreTamperingRule) SupportedTags() []string {
	return []string{}
}

func (r *SharedDatastoreTamperingRule) GenerateRisks(input *types.Model) ([]*types.Risk, error) {
	risks := make([]*types.Risk, 0)
	for _, id := range input.SortedTechnicalAssetIDs() {
		technicalAsset := input.TechnicalAssets[id]
		if technicalAsset.OutOfScope || technicalAsset.Type != types.Datastore {
			continue
		}
		writerBoundaries := make(map[string]bool)
		for _, incomingFlow := range input.IncomingTechnicalCommunicationLinksMappedByTargetId[technicalAsset.Id] {
			source := input.TechnicalAssets[incomingFlow.SourceId]
			if source == nil || incomingFlow.Readonly {
				continue
			}
			writerBoundaries[networkBoundaryIdOf(input, incomingFlow.SourceId)] = true
		}
		if len(writerBoundaries) < 2 {
			continue
		}
		impact := types.LowImpact
		switch input.HighestProcessedIntegrity(technicalAsset) {
		case types.MissionCritical:
			impact = types.HighImpact
		case types.Critical:
			impact = types.MediumImpact
		}
		risks = append(risks, newAssetRisk(r.Category().ID,
			"<b>Shared Datastore Tampering</b> risk at <b>"+technicalAsset.Title+"</b>",
			types.Unlikely, impact, technicalAsset, types.Improbable))
	}
	return risks, nil
}
