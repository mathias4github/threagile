package builtin

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/threagile/threagile/pkg/types"
)


func TestClientReverseEngineeringSensitiveCustomMobileAppCreatesRisk(t *testing.T) {
	app := ptAsset("app", ptTech(types.MobileApp))
	app.CustomDevelopedParts = true
	model := ptModel([]*types.TechnicalAsset{app}, nil, nil)
	ptProcess(model, app, types.Confidential, types.Operational)

	risks, err := NewClientReverseEngineeringRule().GenerateRisks(model)

	require.NoError(t, err)
	require.Len(t, risks, 1)
	assert.Equal(t, "client-reverse-engineering@app", risks[0].SyntheticId)
}

func TestClientReverseEngineeringNoRiskForPublicDataThirdPartyOrServer(t *testing.T) {
	publicApp := ptAsset("app", ptTech(types.MobileApp))
	publicApp.CustomDevelopedParts = true
	model := ptModel([]*types.TechnicalAsset{publicApp}, nil, nil)
	ptProcess(model, publicApp, types.Public, types.Operational)
	risks, _ := NewClientReverseEngineeringRule().GenerateRisks(model)
	assert.Empty(t, risks, "public data")

	thirdParty := ptAsset("app", ptTech(types.Desktop))
	model = ptModel([]*types.TechnicalAsset{thirdParty}, nil, nil)
	ptProcess(model, thirdParty, types.StrictlyConfidential, types.MissionCritical)
	risks, _ = NewClientReverseEngineeringRule().GenerateRisks(model)
	assert.Empty(t, risks, "no custom developed parts")

	server := ptAsset("srv", ptTech(types.WebServer))
	server.CustomDevelopedParts = true
	model = ptModel([]*types.TechnicalAsset{server}, nil, nil)
	ptProcess(model, server, types.StrictlyConfidential, types.MissionCritical)
	risks, _ = NewClientReverseEngineeringRule().GenerateRisks(model)
	assert.Empty(t, risks, "not a client technology")
}
