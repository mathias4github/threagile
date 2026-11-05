package builtin

import (
	"github.com/threagile/threagile/pkg/types"
)

type MailCommandInjectionRule struct{}

func NewMailCommandInjectionRule() *MailCommandInjectionRule {
	return &MailCommandInjectionRule{}
}

func (*MailCommandInjectionRule) Category() *types.RiskCategory {
	return &types.RiskCategory{
		ID:    "mail-command-injection",
		Title: "Mail Command Injection",
		Description: "When mail servers are accessed via SMTP or IMAP and values controlled by a caller end up in the protocol commands or message headers, " +
			"attackers might inject additional commands or headers.",
		Impact: "If this risk is unmitigated, attackers might be able to send mails in the name of the system, read or alter mailboxes of other users, " +
			"or execute unintended mail server commands.",
		ASVS:       "V5 - Validation, Sanitization and Encoding Verification Requirements",
		CheatSheet: "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/10-Testing_for_IMAP_SMTP_Injection",
		Action:     "Mail Injection Prevention",
		Mitigation: "Never build protocol commands or headers from caller-controlled values by string concatenation. Reject line breaks in values used for headers, " +
			"use mail libraries with structured APIs, and validate recipients and mailbox names against an allow-list. When a third-party product is used instead of " +
			"custom developed software, check if the product applies the proper mitigation and ensure a reasonable patch-level.",
		Check:          "Are values used in mail commands and headers validated and are line breaks rejected?",
		Function:       types.Development,
		STRIDE:         types.Tampering,
		DetectionLogic: "In-scope technical assets accessed by in-scope callers via SMTP or IMAP protocols (encrypted or not).",
		RiskAssessment: "The risk rating depends on the sensitivity of the mail server itself and of the data assets processed.",
		FalsePositives: "Mail submission with fixed recipients and header values not consisting of parts controllable by the caller can be considered " +
			"as false positives after individual review.",
		ModelFailurePossibleReason: false,
		CWE:                        77,
	}
}

func (*MailCommandInjectionRule) SupportedTags() []string {
	return []string{}
}

func (r *MailCommandInjectionRule) GenerateRisks(input *types.Model) ([]*types.Risk, error) {
	risks := make([]*types.Risk, 0)
	for _, id := range input.SortedTechnicalAssetIDs() {
		technicalAsset := input.TechnicalAssets[id]
		if technicalAsset.OutOfScope {
			continue
		}
		for _, incomingFlow := range input.IncomingTechnicalCommunicationLinksMappedByTargetId[technicalAsset.Id] {
			source := input.TechnicalAssets[incomingFlow.SourceId]
			if source == nil || source.OutOfScope {
				continue
			}
			if incomingFlow.Protocol != types.SMTP && incomingFlow.Protocol != types.SmtpEncrypted &&
				incomingFlow.Protocol != types.IMAP && incomingFlow.Protocol != types.ImapEncrypted {
				continue
			}
			likelihood := types.Likely
			if incomingFlow.Usage == types.DevOps {
				likelihood = types.Unlikely
			}
			title := "<b>Mail Command Injection</b> risk at <b>" + source.Title + "</b> against mail server <b>" + technicalAsset.Title +
				"</b> via <b>" + incomingFlow.Title + "</b>"
			risk := newLinkRisk(r.Category().ID, title, likelihood, impactByCIA(input, technicalAsset),
				technicalAsset, incomingFlow, types.Possible)
			risk.MostRelevantTechnicalAssetId = source.Id // the injectable code lives in the caller (like ldap-injection)
			risks = append(risks, risk)
		}
	}
	return risks, nil
}
