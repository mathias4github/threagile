package builtin

import (
	"github.com/threagile/threagile/pkg/types"
)

type HttpRequestSmugglingRule struct{}

func NewHttpRequestSmugglingRule() *HttpRequestSmugglingRule {
	return &HttpRequestSmugglingRule{}
}

func (*HttpRequestSmugglingRule) Category() *types.RiskCategory {
	return &types.RiskCategory{
		ID:    "http-request-smuggling",
		Title: "HTTP Request Smuggling",
		Description: "When a front-end component (reverse proxy, load balancer, gateway or WAF) forwards web traffic to a back-end web server, both may interpret " +
			"message boundaries (content length, chunking, header folding) differently. Attackers can exploit such differences to hide a second request inside the first one.",
		Impact: "If this risk is unmitigated, attackers might bypass filtering and access controls of the front-end, poison shared connections or caches, " +
			"and hijack requests of other users.",
		ASVS:       "V13 - API and Web Service Verification Requirements",
		CheatSheet: "https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html",
		Action:     "HTTP Parsing Consistency",
		Mitigation: "Use current versions of front-end and back-end components that parse HTTP identically and reject ambiguous requests. Prefer HTTP/2 or later " +
			"end-to-end between the components, disable connection reuse towards the back-end where possible, and normalize or reject conflicting length headers at the front-end.",
		Check:          "Do front-end and back-end reject ambiguous or malformed HTTP messages in the same way?",
		Function:       types.Operations,
		STRIDE:         types.Tampering,
		DetectionLogic: "In-scope web servers or web applications receiving web traffic forwarded by an in-scope reverse proxy, load balancer, gateway or WAF.",
		RiskAssessment: "The risk rating depends on the sensitivity of the receiving technical asset and of the data assets processed.",
		FalsePositives: "Setups where the front-end and the back-end are the same product with identical parsing, or where the back-end only accepts requests over an " +
			"authenticated, non-shared channel, can be considered as false positives after individual review.",
		ModelFailurePossibleReason: false,
		CWE:                        444,
	}
}

func (*HttpRequestSmugglingRule) SupportedTags() []string {
	return []string{}
}

func (r *HttpRequestSmugglingRule) GenerateRisks(input *types.Model) ([]*types.Risk, error) {
	risks := make([]*types.Risk, 0)
	for _, technicalAsset := range input.TechnicalAssets {
		if technicalAsset.OutOfScope {
			continue
		}
		if !technicalAsset.Technologies.GetAttribute(types.WebApplication, "web_application", types.IsWebService) {
			continue
		}
		for _, incomingFlow := range input.IncomingTechnicalCommunicationLinksMappedByTargetId[technicalAsset.Id] {
			source := input.TechnicalAssets[incomingFlow.SourceId]
			if source == nil || source.OutOfScope {
				continue
			}
			if !source.Technologies.GetAttribute(types.IsTrafficForwarding, types.Gateway) {
				continue
			}
			if !incomingFlow.Protocol.IsPotentialWebAccessProtocol() {
				continue
			}
			likelihood := types.Unlikely
			risks = append(risks, newAssetRisk(r.Category().ID,
				"<b>HTTP Request Smuggling</b> risk at <b>"+technicalAsset.Title+"</b> behind <b>"+source.Title+"</b>",
				likelihood, impactByCIA(input, technicalAsset), technicalAsset, types.Improbable))
			break
		}
	}
	return risks, nil
}
