package builtin

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/threagile/threagile/pkg/types"
)


func TestXmlEntityExpansionDosInternetFacingXmlAssetCreatesRisk(t *testing.T) {
	service := ptAsset("svc", ptTech(types.WebApplication))
	service.Internet = true
	service.DataFormatsAccepted = []types.DataFormat{types.XML}
	service.Availability = types.Critical

	risks, err := NewXmlEntityExpansionDosRule().GenerateRisks(ptModel([]*types.TechnicalAsset{service}, nil, nil))

	require.NoError(t, err)
	require.Len(t, risks, 1)
	assert.Equal(t, types.Likely, risks[0].ExploitationLikelihood)
	assert.Equal(t, types.MediumImpact, risks[0].ExploitationImpact)
}

func TestXmlEntityExpansionDosNoRiskWithoutXmlOrExposure(t *testing.T) {
	noXml := ptAsset("svc", ptTech(types.WebApplication))
	noXml.Internet = true
	noXml.DataFormatsAccepted = []types.DataFormat{types.JSON}
	risks, _ := NewXmlEntityExpansionDosRule().GenerateRisks(ptModel([]*types.TechnicalAsset{noXml}, nil, nil))
	assert.Empty(t, risks)

	internal := ptAsset("svc", ptTech(types.WebApplication))
	internal.DataFormatsAccepted = []types.DataFormat{types.XML}
	caller := ptAsset("caller", ptTech(types.WebApplication))
	same := ptBoundary("tb", types.NetworkOnPrem)
	model := ptModel([]*types.TechnicalAsset{internal, caller}, []*types.CommunicationLink{ptLink("l", "caller", "svc", types.HTTPS)},
		map[string]*types.TrustBoundary{"svc": same, "caller": same})
	risks, _ = NewXmlEntityExpansionDosRule().GenerateRisks(model)
	assert.Empty(t, risks)
}

func TestXmlEntityExpansionDosSoapAcrossBoundaryCreatesRiskWithLowerImpactWhenRedundant(t *testing.T) {
	soap := ptAsset("soap", ptTech(types.WebServiceSOAP))
	soap.Availability = types.MissionCritical
	soap.Redundant = true
	caller := ptAsset("caller", ptTech(types.WebApplication))
	model := ptModel([]*types.TechnicalAsset{soap, caller}, []*types.CommunicationLink{ptLink("l", "caller", "soap", types.HTTPS)},
		map[string]*types.TrustBoundary{"soap": ptBoundary("tb1", types.NetworkOnPrem), "caller": ptBoundary("tb2", types.NetworkOnPrem)})

	risks, err := NewXmlEntityExpansionDosRule().GenerateRisks(model)

	require.NoError(t, err)
	require.Len(t, risks, 1)
	assert.Equal(t, types.LowImpact, risks[0].ExploitationImpact)
}
