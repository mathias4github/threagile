package builtin

import (
	"github.com/threagile/threagile/pkg/types"
)

type XmlEntityExpansionDosRule struct{}

func NewXmlEntityExpansionDosRule() *XmlEntityExpansionDosRule {
	return &XmlEntityExpansionDosRule{}
}

func (*XmlEntityExpansionDosRule) Category() *types.RiskCategory {
	return &types.RiskCategory{
		ID:    "xml-entity-expansion-dos",
		Title: "XML Entity Expansion and Oversized Payload DoS",
		Description: "XML and SOAP processors can be forced to consume huge amounts of memory and CPU by documents that expand nested or recursive entities, " +
			"contain extremely deep nesting, huge attribute values, or very large arrays of elements.",
		Impact:     "If this risk is unmitigated, attackers might be able to make the technical asset unavailable with very small requests.",
		ASVS:       "V13 - API and Web Service Verification Requirements",
		CheatSheet: "https://cheatsheetseries.owasp.org/cheatsheets/XML_Security_Cheat_Sheet.html",
		Action:     "XML Resource Limits",
		Mitigation: "Disable entity expansion and DTD processing where not needed, and configure limits for document size, nesting depth, number of elements, " +
			"attribute size and entity expansion count in the XML or SOAP stack. Enforce request size limits and timeouts already at the front-end.",
		Check:          "Are DTDs disabled and are size, depth and expansion limits configured for XML processing?",
		Function:       types.Development,
		STRIDE:         types.DenialOfService,
		DetectionLogic: "In-scope technical assets accepting XML data or offering SOAP web services that are accessed from the internet or across a trust boundary.",
		RiskAssessment: "The risk rating depends on the availability rating of the technical asset and of the data assets processed; redundancy lowers the impact.",
		FalsePositives: "XML processing with hardened parsers and enforced resource limits, or assets only reachable by trusted callers in the same trust boundary, " +
			"can be considered as false positives after individual review.",
		ModelFailurePossibleReason: false,
		CWE:                        776,
	}
}

func (*XmlEntityExpansionDosRule) SupportedTags() []string {
	return []string{}
}

func (r *XmlEntityExpansionDosRule) GenerateRisks(input *types.Model) ([]*types.Risk, error) {
	risks := make([]*types.Risk, 0)
	for _, technicalAsset := range input.TechnicalAssets {
		if technicalAsset.OutOfScope {
			continue
		}
		acceptsXml := technicalAsset.Technologies.GetAttribute(types.WebServiceSOAP)
		for _, format := range technicalAsset.DataFormatsAccepted {
			if format == types.XML {
				acceptsXml = true
			}
		}
		if !acceptsXml {
			continue
		}
		exposed := technicalAsset.Internet
		for _, incomingFlow := range input.IncomingTechnicalCommunicationLinksMappedByTargetId[technicalAsset.Id] {
			source := input.TechnicalAssets[incomingFlow.SourceId]
			if source != nil && !source.OutOfScope && isAcrossAnyTrustBoundary(input, incomingFlow) {
				exposed = true
			}
		}
		if !exposed {
			continue
		}
		likelihood := types.Unlikely
		if technicalAsset.Internet {
			likelihood = types.Likely
		}
		impact := types.LowImpact
		if !technicalAsset.Redundant && input.HighestProcessedAvailability(technicalAsset) >= types.Critical {
			impact = types.MediumImpact
		}
		risks = append(risks, newAssetRisk(r.Category().ID,
			"<b>XML Entity Expansion and Oversized Payload DoS</b> risk at <b>"+technicalAsset.Title+"</b>",
			likelihood, impact, technicalAsset, types.Improbable))
	}
	return risks, nil
}
