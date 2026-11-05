package builtin

import (
	"sort"

	"github.com/threagile/threagile/pkg/types"
)

// sortedIncomingLinks returns the incoming links of an asset in a deterministic order without mutating the model.
func sortedIncomingLinks(input *types.Model, assetId string) []*types.CommunicationLink {
	original := input.IncomingTechnicalCommunicationLinksMappedByTargetId[assetId]
	links := make([]*types.CommunicationLink, len(original))
	copy(links, original)
	sort.Sort(types.ByTechnicalCommunicationLinkIdSort(links))
	return links
}

// sortedDataAssetIDs returns the data asset ids in a deterministic order.
func sortedDataAssetIDs(input *types.Model) []string {
	ids := make([]string, 0, len(input.DataAssets))
	for id := range input.DataAssets {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

// isSensitiveAsset: the asset itself or the data it processes is rated confidential / critical or higher.
func isSensitiveAsset(input *types.Model, asset *types.TechnicalAsset) bool {
	return input.HighestProcessedConfidentiality(asset) >= types.Confidential ||
		input.HighestProcessedIntegrity(asset) >= types.Critical ||
		input.HighestProcessedAvailability(asset) >= types.Critical
}

// isUntrustedCaller: the caller is internet-facing, operated by humans or located in another network trust boundary.
func isUntrustedCaller(input *types.Model, source *types.TechnicalAsset, link *types.CommunicationLink) bool {
	return source.Internet || source.UsedAsClientByHuman || isAcrossTrustBoundaryNetworkOnly(input, link)
}

// processedSensitivityScore rates an asset by the highest ratings of itself and the data it processes.
func processedSensitivityScore(input *types.Model, asset *types.TechnicalAsset) float64 {
	return input.HighestProcessedConfidentiality(asset).AttackerAttractivenessForAsset() +
		input.HighestProcessedIntegrity(asset).AttackerAttractivenessForAsset() +
		input.HighestProcessedAvailability(asset).AttackerAttractivenessForAsset()
}
