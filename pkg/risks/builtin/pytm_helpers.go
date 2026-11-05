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

// isWebApplicationAttribute is the technology attribute shared by web-application, web-server and application-server.
const isWebApplicationAttribute = "web_application"

// networkBoundaryIdOf returns the id of the nearest network trust boundary around the asset
// (walking up through nested non-network boundaries), or "" if the asset is in no network boundary.
func networkBoundaryIdOf(input *types.Model, assetId string) string {
	boundary := input.DirectContainingTrustBoundaryMappedByTechnicalAssetId[assetId]
	for depth := 0; boundary != nil && depth < 100; depth++ {
		if boundary.Type.IsNetworkBoundary() {
			return boundary.Id
		}
		boundary = input.FindParentTrustBoundary(boundary)
	}
	return ""
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
