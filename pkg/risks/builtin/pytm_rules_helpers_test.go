package builtin

import (
	"github.com/threagile/threagile/pkg/types"
)

// ptTech builds a technology that carries its own name as attribute plus the given extra attributes.
func ptTech(name string, extraAttributes ...string) *types.Technology {
	attributes := map[string]bool{name: true}
	for _, attribute := range extraAttributes {
		attributes[attribute] = true
	}
	return &types.Technology{Name: name, Attributes: attributes}
}

func ptAsset(id string, technology *types.Technology) *types.TechnicalAsset {
	asset := &types.TechnicalAsset{Id: id, Title: id}
	if technology != nil {
		asset.Technologies = types.TechnologyList{technology}
	}
	return asset
}

// ptModel assembles a model from assets and links (links are registered at their target) and an optional
// asset-id to trust-boundary-id mapping.
func ptModel(assets []*types.TechnicalAsset, links []*types.CommunicationLink, boundaries map[string]*types.TrustBoundary) *types.Model {
	model := &types.Model{
		TechnicalAssets: make(map[string]*types.TechnicalAsset),
		DataAssets:      make(map[string]*types.DataAsset),
		IncomingTechnicalCommunicationLinksMappedByTargetId:   make(map[string][]*types.CommunicationLink),
		DirectContainingTrustBoundaryMappedByTechnicalAssetId: make(map[string]*types.TrustBoundary),
	}
	for _, asset := range assets {
		model.TechnicalAssets[asset.Id] = asset
	}
	for _, link := range links {
		model.IncomingTechnicalCommunicationLinksMappedByTargetId[link.TargetId] = append(model.IncomingTechnicalCommunicationLinksMappedByTargetId[link.TargetId], link)
		if source, ok := model.TechnicalAssets[link.SourceId]; ok {
			source.CommunicationLinks = append(source.CommunicationLinks, link)
		}
	}
	for assetId, boundary := range boundaries {
		model.DirectContainingTrustBoundaryMappedByTechnicalAssetId[assetId] = boundary
		ptRegisterBoundary(model, boundary)
	}
	return model
}

// ptRegisterBoundary makes the boundary known to the model so that parent lookups work.
func ptRegisterBoundary(model *types.Model, boundary *types.TrustBoundary) {
	if model.TrustBoundaries == nil {
		model.TrustBoundaries = make(map[string]*types.TrustBoundary)
	}
	model.TrustBoundaries[boundary.Id] = boundary
}

// ptNest declares child as nested inside parent (parent needs no directly contained asset).
func ptNest(model *types.Model, parent *types.TrustBoundary, child *types.TrustBoundary) {
	parent.TrustBoundariesNested = append(parent.TrustBoundariesNested, child.Id)
	ptRegisterBoundary(model, parent)
	ptRegisterBoundary(model, child)
}

func ptLink(id, source, target string, protocol types.Protocol) *types.CommunicationLink {
	return &types.CommunicationLink{Id: id, Title: id, SourceId: source, TargetId: target, Protocol: protocol}
}

func ptBoundary(id string, boundaryType types.TrustBoundaryType) *types.TrustBoundary {
	return &types.TrustBoundary{Id: id, Title: id, Type: boundaryType}
}

// ptProcess makes the asset process a data asset with the given ratings.
func ptProcess(model *types.Model, asset *types.TechnicalAsset, confidentiality types.Confidentiality, integrity types.Criticality) {
	ptProcessWithAvailability(model, asset, confidentiality, integrity, types.Archive)
}

func ptProcessWithAvailability(model *types.Model, asset *types.TechnicalAsset, confidentiality types.Confidentiality, integrity types.Criticality, availability types.Criticality) {
	dataAsset := &types.DataAsset{Id: "da-" + asset.Id, Title: "da-" + asset.Id, Confidentiality: confidentiality, Integrity: integrity, Availability: availability}
	model.DataAssets[dataAsset.Id] = dataAsset
	asset.DataAssetsProcessed = append(asset.DataAssetsProcessed, dataAsset.Id)
}
