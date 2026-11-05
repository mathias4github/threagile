package builtin

import (
	"github.com/threagile/threagile/pkg/types"
)

// impactByCIA derives a base impact from the highest rating of the data processed by the asset.
func impactByCIA(input *types.Model, asset *types.TechnicalAsset) types.RiskExploitationImpact {
	confidentiality := input.HighestProcessedConfidentiality(asset)
	integrity := input.HighestProcessedIntegrity(asset)
	if confidentiality == types.StrictlyConfidential || integrity == types.MissionCritical {
		return types.HighImpact
	}
	if confidentiality == types.Confidential || integrity == types.Critical {
		return types.MediumImpact
	}
	return types.LowImpact
}

// boundaryIdOf returns the id of the trust boundary directly containing the asset ("" if none).
func boundaryIdOf(input *types.Model, assetId string) string {
	boundary := input.DirectContainingTrustBoundaryMappedByTechnicalAssetId[assetId]
	if boundary == nil {
		return ""
	}
	return boundary.Id
}

func isAcrossAnyTrustBoundary(input *types.Model, link *types.CommunicationLink) bool {
	return boundaryIdOf(input, link.SourceId) != boundaryIdOf(input, link.TargetId)
}

func newAssetRisk(ruleId string, title string, likelihood types.RiskExploitationLikelihood, impact types.RiskExploitationImpact,
	asset *types.TechnicalAsset, probability types.DataBreachProbability) *types.Risk {
	risk := &types.Risk{
		CategoryId:                   ruleId,
		Severity:                     types.CalculateSeverity(likelihood, impact),
		ExploitationLikelihood:       likelihood,
		ExploitationImpact:           impact,
		Title:                        title,
		MostRelevantTechnicalAssetId: asset.Id,
		DataBreachProbability:        probability,
		DataBreachTechnicalAssetIDs:  []string{asset.Id},
	}
	risk.SyntheticId = ruleId + "@" + asset.Id
	return risk
}

func newLinkRisk(ruleId string, title string, likelihood types.RiskExploitationLikelihood, impact types.RiskExploitationImpact,
	target *types.TechnicalAsset, link *types.CommunicationLink, probability types.DataBreachProbability) *types.Risk {
	risk := newAssetRisk(ruleId, title, likelihood, impact, target, probability)
	risk.MostRelevantCommunicationLinkId = link.Id
	risk.SyntheticId = ruleId + "@" + link.SourceId + "@" + target.Id + "@" + link.SourceId + ">" + link.Id
	return risk
}
