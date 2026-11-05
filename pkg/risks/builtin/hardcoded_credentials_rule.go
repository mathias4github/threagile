package builtin

import (
	"github.com/threagile/threagile/pkg/types"
)

type HardcodedCredentialsRule struct{}

func NewHardcodedCredentialsRule() *HardcodedCredentialsRule {
	return &HardcodedCredentialsRule{}
}

func (*HardcodedCredentialsRule) Category() *types.RiskCategory {
	return &types.RiskCategory{
		ID:    "hardcoded-credentials",
		Title: "Hard-coded Credentials",
		Description: "Credentials, keys or tokens that are baked into source code, images, configuration files or clients cannot be rotated without a release, " +
			"are shared by all installations and end up in repositories, build artifacts and backups.",
		Impact: "If this risk is unmitigated, anyone with access to the code, artifact or client might extract the secret and use it against all systems " +
			"sharing it, and a leak cannot be contained by rotation.",
		ASVS:       "V2 - Authentication Verification Requirements",
		CheatSheet: "https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html",
		Action:     "Secrets Management",
		Mitigation: "Move the secret into a vault or the platform's secret store, inject it at runtime, give each installation its own credential, rotate it regularly " +
			"and scan repositories and artifacts for secrets. Mark the data asset accordingly once the secret is no longer hard-coded.",
		Check:                      "Is the secret provided at runtime from a secret store and rotatable without a release?",
		Function:                   types.Development,
		STRIDE:                     types.InformationDisclosure,
		DetectionLogic:             "Data assets tagged with credentials-hardcoded that are processed or stored by in-scope technical assets.",
		RiskAssessment:             "The risk rating depends on the confidentiality rating of the data asset.",
		FalsePositives:             "Secrets that only protect test or demo environments can be considered as false positives after individual review.",
		ModelFailurePossibleReason: false,
		CWE:                        798,
	}
}

func (*HardcodedCredentialsRule) SupportedTags() []string {
	return []string{"credentials-hardcoded"}
}

func (r *HardcodedCredentialsRule) GenerateRisks(input *types.Model) ([]*types.Risk, error) {
	risks := make([]*types.Risk, 0)
	for _, dataAssetId := range sortedDataAssetIDs(input) {
		dataAsset := input.DataAssets[dataAssetId]
		if !dataAsset.IsTaggedWithAny(r.SupportedTags()...) {
			continue
		}
		var holder *types.TechnicalAsset
		for _, id := range input.SortedTechnicalAssetIDs() {
			technicalAsset := input.TechnicalAssets[id]
			if technicalAsset.OutOfScope {
				continue
			}
			if contains(technicalAsset.DataAssetsStored, dataAsset.Id) {
				holder = technicalAsset
				break
			}
			if holder == nil && contains(technicalAsset.DataAssetsProcessed, dataAsset.Id) {
				holder = technicalAsset
			}
		}
		if holder == nil {
			continue
		}
		impact := types.MediumImpact
		if dataAsset.Confidentiality >= types.Confidential {
			impact = types.HighImpact
		}
		risk := newAssetRisk(r.Category().ID,
			"<b>Hard-coded Credentials</b> risk for data asset <b>"+dataAsset.Title+"</b> (held by <b>"+holder.Title+"</b>)",
			types.Likely, impact, holder, types.Probable)
		risk.MostRelevantDataAssetId = dataAsset.Id
		risk.SyntheticId = r.Category().ID + "@" + dataAsset.Id
		risks = append(risks, risk)
	}
	return risks, nil
}
