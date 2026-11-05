package builtin

import (
	"github.com/threagile/threagile/pkg/types"
)

type OsCommandInjectionRule struct{}

func NewOsCommandInjectionRule() *OsCommandInjectionRule {
	return &OsCommandInjectionRule{}
}

func (*OsCommandInjectionRule) Category() *types.RiskCategory {
	return &types.RiskCategory{
		ID:    "os-command-injection",
		Title: "OS Command Injection",
		Description: "Custom developed components that execute operating system commands or spawn processes can be made to run attacker-chosen commands when " +
			"caller-controlled values reach the command line or shell.",
		Impact:     "If this risk is unmitigated, attackers might execute arbitrary commands with the privileges of the component and take over the host.",
		ASVS:       "V5 - Validation, Sanitization and Encoding Verification Requirements",
		CheatSheet: "https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html",
		Action:     "OS Command Injection Prevention",
		Mitigation: "Avoid calling the shell; use library functions or parameterized process APIs with argument arrays, validate caller-controlled values against " +
			"a strict allow-list, and run the component with minimal privileges in a sandbox or container.",
		Check:    "Are OS commands built without a shell and with validated, parameterized arguments?",
		Function: types.Development,
		STRIDE:   types.ElevationOfPrivilege,
		DetectionLogic: "In-scope custom developed technical assets tagged with executes-os-commands that are called by in-scope assets which are internet-facing, " +
			"used by humans or located in another network trust boundary.",
		RiskAssessment:             "The risk rating depends on the sensitivity of the technical asset itself and of the data assets processed; the impact is at least medium.",
		FalsePositives:             "Components executing only fixed commands without any caller-controlled part can be considered as false positives after individual review.",
		ModelFailurePossibleReason: false,
		CWE:                        78,
	}
}

func (*OsCommandInjectionRule) SupportedTags() []string {
	return []string{"executes-os-commands"}
}

func (r *OsCommandInjectionRule) GenerateRisks(input *types.Model) ([]*types.Risk, error) {
	risks := make([]*types.Risk, 0)
	for _, id := range input.SortedTechnicalAssetIDs() {
		technicalAsset := input.TechnicalAssets[id]
		if technicalAsset.OutOfScope || !technicalAsset.CustomDevelopedParts || !technicalAsset.IsTaggedWithAny(r.SupportedTags()...) {
			continue
		}
		for _, incomingFlow := range sortedIncomingLinks(input, technicalAsset.Id) {
			source := input.TechnicalAssets[incomingFlow.SourceId]
			if source == nil || source.OutOfScope || !isUntrustedCaller(input, source, incomingFlow) {
				continue
			}
			impact := impactByCIA(input, technicalAsset)
			if impact < types.MediumImpact {
				impact = types.MediumImpact
			}
			risks = append(risks, newAssetRisk(r.Category().ID,
				"<b>OS Command Injection</b> risk at <b>"+technicalAsset.Title+"</b>",
				types.Likely, impact, technicalAsset, types.Probable))
			break
		}
	}
	return risks, nil
}
