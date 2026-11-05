package builtin

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/threagile/threagile/pkg/types"
)

func TestXmlSchemaPoisoningUnauthorizedCallerOfXmlAssetCreatesRisk(t *testing.T) {
	target := ptAsset("svc", ptTech(types.WebApplication))
	target.DataFormatsAccepted = []types.DataFormat{types.XML}
	caller := ptAsset("caller", ptTech(types.WebApplication))
	link := ptLink("l", "caller", "svc", types.HTTPS)
	link.Authorization = types.NoneAuthorization

	risks, err := NewXmlSchemaPoisoningRule().GenerateRisks(ptModel([]*types.TechnicalAsset{target, caller}, []*types.CommunicationLink{link}, nil))

	require.NoError(t, err)
	require.Len(t, risks, 1)
	assert.Equal(t, "xml-schema-poisoning@caller@svc@caller>l", risks[0].SyntheticId)
}

func TestXmlSchemaPoisoningNoRiskWhenAuthorizedOrNoXml(t *testing.T) {
	build := func(format types.DataFormat, authorization types.Authorization) *types.Model {
		target := ptAsset("svc", ptTech(types.WebApplication))
		target.DataFormatsAccepted = []types.DataFormat{format}
		caller := ptAsset("caller", ptTech(types.WebApplication))
		link := ptLink("l", "caller", "svc", types.HTTPS)
		link.Authorization = authorization
		return ptModel([]*types.TechnicalAsset{target, caller}, []*types.CommunicationLink{link}, nil)
	}
	for name, model := range map[string]*types.Model{
		"authorized": build(types.XML, types.TechnicalUser),
		"json only":  build(types.JSON, types.NoneAuthorization),
	} {
		risks, err := NewXmlSchemaPoisoningRule().GenerateRisks(model)
		assert.NoError(t, err, name)
		assert.Empty(t, risks, name)
	}
}
