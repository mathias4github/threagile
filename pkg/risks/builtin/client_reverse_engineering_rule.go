package builtin

import (
	"github.com/threagile/threagile/pkg/types"
)

type ClientReverseEngineeringRule struct{}

func NewClientReverseEngineeringRule() *ClientReverseEngineeringRule {
	return &ClientReverseEngineeringRule{}
}

func (*ClientReverseEngineeringRule) Category() *types.RiskCategory {
	return &types.RiskCategory{
		ID:    "client-reverse-engineering",
		Title: "Client Reverse Engineering",
		Description: "Software and devices in the hands of users (mobile apps, desktop applications, IoT devices) can be analyzed by attackers with physical " +
			"or full local access. Embedded secrets, keys, proprietary logic and protocol details can be extracted and used against the backend.",
		Impact:     "If this risk is unmitigated, attackers might extract secrets or sensitive data, clone or tamper with the client, or find weaknesses of the backend.",
		ASVS:       "V14 - Configuration Verification Requirements",
		CheatSheet: "https://cheatsheetseries.owasp.org/cheatsheets/Mobile_Application_Security_Cheat_Sheet.html",
		Action:     "Client Hardening",
		Mitigation: "Do not ship long-lived shared secrets inside clients and assume that all client code and traffic is known to attackers. Use per-device credentials " +
			"stored in hardware-backed key stores, encrypt locally stored data, apply code signing and obfuscation as additional layers, and enforce all rules in the backend.",
		Check:    "Are no shared secrets embedded in the client and is local data protected by hardware-backed storage?",
		Function: types.Development,
		STRIDE:   types.InformationDisclosure,
		DetectionLogic: "In-scope mobile apps, desktop applications and IoT devices with custom developed parts that process data rated confidential or " +
			"critical in integrity or higher.",
		RiskAssessment:             "The risk rating depends on the sensitivity of the data assets processed by the client.",
		FalsePositives:             "Clients that only display public or short-lived data and hold no secrets can be considered as false positives after individual review.",
		ModelFailurePossibleReason: false,
		CWE:                        693,
	}
}

func (*ClientReverseEngineeringRule) SupportedTags() []string {
	return []string{}
}

func (r *ClientReverseEngineeringRule) GenerateRisks(input *types.Model) ([]*types.Risk, error) {
	risks := make([]*types.Risk, 0)
	for _, id := range input.SortedTechnicalAssetIDs() {
		technicalAsset := input.TechnicalAssets[id]
		if technicalAsset.OutOfScope || !technicalAsset.CustomDevelopedParts {
			continue
		}
		if !technicalAsset.Technologies.GetAttribute(types.MobileApp, types.Desktop, types.IoTDevice) {
			continue
		}
		impact := impactByCIA(input, technicalAsset)
		if impact == types.LowImpact {
			continue
		}
		risks = append(risks, newAssetRisk(r.Category().ID,
			"<b>Client Reverse Engineering</b> risk at <b>"+technicalAsset.Title+"</b>",
			types.Unlikely, impact, technicalAsset, types.Possible))
	}
	return risks, nil
}
