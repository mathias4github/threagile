package builtin

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/threagile/threagile/pkg/types"
)

func TestMailCommandInjectionSmtpLinkCreatesRisk(t *testing.T) {
	app := ptAsset("app", ptTech(types.WebApplication))
	mail := ptAsset("mail", ptTech(types.MailServer))
	model := ptModel([]*types.TechnicalAsset{app, mail}, []*types.CommunicationLink{ptLink("send", "app", "mail", types.SmtpEncrypted)}, nil)

	risks, err := NewMailCommandInjectionRule().GenerateRisks(model)

	require.NoError(t, err)
	require.Len(t, risks, 1)
	assert.Equal(t, "mail-command-injection@app@mail@app>send", risks[0].SyntheticId)
	assert.Equal(t, types.Likely, risks[0].ExploitationLikelihood)
}

func TestMailCommandInjectionNoRiskForOtherProtocolOrOutOfScopeSource(t *testing.T) {
	app := ptAsset("app", ptTech(types.WebApplication))
	mail := ptAsset("mail", ptTech(types.MailServer))
	other := ptModel([]*types.TechnicalAsset{app, mail}, []*types.CommunicationLink{ptLink("l", "app", "mail", types.HTTPS)}, nil)
	risks, _ := NewMailCommandInjectionRule().GenerateRisks(other)
	assert.Empty(t, risks)

	app2 := ptAsset("app", ptTech(types.WebApplication))
	app2.OutOfScope = true
	skipped := ptModel([]*types.TechnicalAsset{app2, ptAsset("mail", ptTech(types.MailServer))}, []*types.CommunicationLink{ptLink("l", "app", "mail", types.IMAP)}, nil)
	risks, _ = NewMailCommandInjectionRule().GenerateRisks(skipped)
	assert.Empty(t, risks)
}
