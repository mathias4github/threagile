package builtin

import (
	"github.com/threagile/threagile/pkg/types"
)

type AiSensitiveDataExposureRule struct{}

func NewAiSensitiveDataExposureRule() *AiSensitiveDataExposureRule {
	return &AiSensitiveDataExposureRule{}
}

func (*AiSensitiveDataExposureRule) Category() *types.RiskCategory {
	return &types.RiskCategory{
		ID:    "ai-sensitive-data-exposure",
		Title: "Sensitive Data Exposure through AI Component",
		Description: "AI components that process confidential data and are run by a cloud provider, or that hand their results to less protected parties, " +
			"may leak that data through the provider's handling (logging, retention, training) or through their own output.",
		Impact:     "If this risk is unmitigated, confidential data might leave the controlled environment or be revealed to unauthorized recipients in generated output.",
		ASVS:       "V8 - Data Protection Verification Requirements",
		CheatSheet: "https://cheatsheetseries.owasp.org/cheatsheets/Secure_AI_Model_Ops_Cheat_Sheet.html",
		Action:     "AI Data Protection",
		Mitigation: "Minimize and pseudonymize the data sent to AI components, use providers and contract terms that exclude retention and training on your data, " +
			"prefer self-hosted models for highly sensitive data, and filter output before it reaches less trusted recipients.",
		Check:    "Is the data sent to the AI component minimized, and are provider terms and output filtering in place?",
		Function: types.Architecture,
		STRIDE:   types.InformationDisclosure,
		DetectionLogic: "In-scope AI technical assets processing data rated confidential or higher that are located in a cloud provider trust boundary " +
			"or have outgoing links to internet-facing or out-of-scope assets.",
		RiskAssessment: "The risk rating depends on the confidentiality rating of the data assets processed.",
		FalsePositives: "AI components with contractually and technically guaranteed isolation, or whose output is fully reviewed before release, " +
			"can be considered as false positives after individual review.",
		ModelFailurePossibleReason: false,
		CWE:                        200,
	}
}

func (*AiSensitiveDataExposureRule) SupportedTags() []string {
	return []string{}
}

func (r *AiSensitiveDataExposureRule) GenerateRisks(input *types.Model) ([]*types.Risk, error) {
	risks := make([]*types.Risk, 0)
	for _, technicalAsset := range input.TechnicalAssets {
		if technicalAsset.OutOfScope || !technicalAsset.Technologies.GetAttribute(types.AI) {
			continue
		}
		confidentiality := input.HighestProcessedConfidentiality(technicalAsset)
		if confidentiality < types.Confidential {
			continue
		}
		if !r.inCloudBoundary(input, technicalAsset) && !r.hasLessProtectedRecipient(input, technicalAsset) {
			continue
		}
		impact := types.MediumImpact
		probability := types.Possible
		if confidentiality == types.StrictlyConfidential {
			impact = types.HighImpact
			probability = types.Probable
		}
		risks = append(risks, newAssetRisk(r.Category().ID,
			"<b>Sensitive Data Exposure through AI Component</b> risk at <b>"+technicalAsset.Title+"</b>",
			types.Unlikely, impact, technicalAsset, probability))
	}
	return risks, nil
}

func (r *AiSensitiveDataExposureRule) inCloudBoundary(input *types.Model, technicalAsset *types.TechnicalAsset) bool {
	boundary := input.DirectContainingTrustBoundaryMappedByTechnicalAssetId[technicalAsset.Id]
	for depth := 0; boundary != nil && depth < 100; depth++ {
		if boundary.Type == types.NetworkCloudProvider {
			return true
		}
		boundary = input.FindParentTrustBoundary(boundary)
	}
	return false
}

func (r *AiSensitiveDataExposureRule) hasLessProtectedRecipient(input *types.Model, technicalAsset *types.TechnicalAsset) bool {
	for _, link := range technicalAsset.CommunicationLinks {
		target := input.TechnicalAssets[link.TargetId]
		if target != nil && (target.Internet || target.OutOfScope) {
			return true
		}
	}
	return false
}
