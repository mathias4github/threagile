package builtin

import (
	"github.com/threagile/threagile/pkg/types"
)

type InternetExposedDatastoreRule struct{}

func NewInternetExposedDatastoreRule() *InternetExposedDatastoreRule {
	return &InternetExposedDatastoreRule{}
}

func (*InternetExposedDatastoreRule) Category() *types.RiskCategory {
	return &types.RiskCategory{
		ID:    "internet-exposed-datastore",
		Title: "Internet-Exposed Datastore",
		Description: "Datastores (databases, file and object storage, snapshots) that are directly reachable from the internet are found within minutes by " +
			"scanners. A misconfigured policy, a weak credential or a product vulnerability then exposes all stored data at once.",
		Impact:     "If this risk is unmitigated, attackers might read or alter the complete content of the datastore without passing any application logic.",
		ASVS:       "V4 - Access Control Verification Requirements",
		CheatSheet: "https://cheatsheetseries.owasp.org/cheatsheets/Database_Security_Cheat_Sheet.html",
		Action:     "Datastore Encapsulation",
		Mitigation: "Place datastores in private networks reachable only through the applications that own them, remove public access settings of cloud storage " +
			"and snapshots, enforce authentication and encryption for every access path, and audit the exposure regularly with external scans.",
		Check:                      "Is the datastore unreachable from the internet and is public sharing of its storage and snapshots disabled?",
		Function:                   types.Operations,
		STRIDE:                     types.InformationDisclosure,
		DetectionLogic:             "In-scope datastores marked as internet-facing that store data rated confidential or higher.",
		RiskAssessment:             "The risk rating depends on the confidentiality rating of the data assets stored.",
		FalsePositives:             "Datastores that are internet-facing by design and only hold public content can be considered as false positives after individual review.",
		ModelFailurePossibleReason: false,
		CWE:                        284,
	}
}

func (*InternetExposedDatastoreRule) SupportedTags() []string {
	return []string{}
}

func (r *InternetExposedDatastoreRule) GenerateRisks(input *types.Model) ([]*types.Risk, error) {
	risks := make([]*types.Risk, 0)
	for _, id := range input.SortedTechnicalAssetIDs() {
		technicalAsset := input.TechnicalAssets[id]
		if technicalAsset.OutOfScope || technicalAsset.Type != types.Datastore || !technicalAsset.Internet {
			continue
		}
		confidentiality := input.HighestStoredConfidentiality(technicalAsset)
		if confidentiality < types.Confidential {
			continue
		}
		impact := types.MediumImpact
		if confidentiality == types.StrictlyConfidential {
			impact = types.HighImpact
		}
		risks = append(risks, newAssetRisk(r.Category().ID,
			"<b>Internet-Exposed Datastore</b> risk at <b>"+technicalAsset.Title+"</b>",
			types.Likely, impact, technicalAsset, types.Probable))
	}
	return risks, nil
}
