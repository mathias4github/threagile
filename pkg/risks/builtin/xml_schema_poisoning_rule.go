package builtin

import (
	"github.com/threagile/threagile/pkg/types"
)

type XmlSchemaPoisoningRule struct{}

func NewXmlSchemaPoisoningRule() *XmlSchemaPoisoningRule {
	return &XmlSchemaPoisoningRule{}
}

func (*XmlSchemaPoisoningRule) Category() *types.RiskCategory {
	return &types.RiskCategory{
		ID:    "xml-schema-poisoning",
		Title: "XML Schema Poisoning",
		Description: "If callers may send XML to an XML-processing technical asset without any authorization, they can also supply or reference their own schemas " +
			"or definitions, and thereby change how documents are validated and interpreted.",
		Impact:     "If this risk is unmitigated, attackers might bypass validation of XML documents or alter the interpretation of data by the receiving asset.",
		ASVS:       "V13 - API and Web Service Verification Requirements",
		CheatSheet: "https://cheatsheetseries.owasp.org/cheatsheets/XML_Security_Cheat_Sheet.html",
		Action:     "Schema Pinning",
		Mitigation: "Validate XML only against locally stored and trusted schemas, never against schemas supplied or referenced by the caller, and authorize " +
			"callers of the XML interface.",
		Check:                      "Are only trusted, locally stored schemas used and are callers authorized?",
		Function:                   types.Development,
		STRIDE:                     types.Tampering,
		DetectionLogic:             "In-scope technical assets accepting XML that are called by in-scope assets via communication links without authorization.",
		RiskAssessment:             "The risk rating depends on the integrity rating of the technical asset and of the data assets processed.",
		FalsePositives:             "XML interfaces using fixed local schemas and rejecting DTD and schema references can be considered as false positives after individual review.",
		ModelFailurePossibleReason: false,
		CWE:                        91,
	}
}

func (*XmlSchemaPoisoningRule) SupportedTags() []string {
	return []string{}
}

func (r *XmlSchemaPoisoningRule) GenerateRisks(input *types.Model) ([]*types.Risk, error) {
	risks := make([]*types.Risk, 0)
	for _, technicalAsset := range input.TechnicalAssets {
		if technicalAsset.OutOfScope {
			continue
		}
		acceptsXml := false
		for _, format := range technicalAsset.DataFormatsAccepted {
			if format == types.XML {
				acceptsXml = true
			}
		}
		if !acceptsXml {
			continue
		}
		for _, incomingFlow := range input.IncomingTechnicalCommunicationLinksMappedByTargetId[technicalAsset.Id] {
			source := input.TechnicalAssets[incomingFlow.SourceId]
			if source == nil || source.OutOfScope || incomingFlow.Authorization != types.NoneAuthorization {
				continue
			}
			impact := types.LowImpact
			if input.HighestProcessedIntegrity(technicalAsset) >= types.Critical {
				impact = types.MediumImpact
			}
			title := "<b>XML Schema Poisoning</b> risk at <b>" + technicalAsset.Title + "</b> via <b>" + incomingFlow.Title + "</b>"
			risks = append(risks, newLinkRisk(r.Category().ID, title, types.Unlikely, impact, technicalAsset, incomingFlow, types.Improbable))
		}
	}
	return risks, nil
}
