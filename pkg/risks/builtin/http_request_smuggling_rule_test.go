package builtin

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/threagile/threagile/pkg/types"
)


func TestHttpRequestSmugglingProxyToWebServerCreatesRisk(t *testing.T) {
	proxy := ptAsset("proxy", ptTech(types.ReverseProxy, types.IsTrafficForwarding))
	web := ptAsset("web", ptTech(types.WebServer, "web_application"))
	model := ptModel([]*types.TechnicalAsset{proxy, web}, []*types.CommunicationLink{ptLink("l1", "proxy", "web", types.HTTPS)}, nil)

	risks, err := NewHttpRequestSmugglingRule().GenerateRisks(model)

	require.NoError(t, err)
	require.Len(t, risks, 1)
	assert.Equal(t, "http-request-smuggling@web", risks[0].SyntheticId)
	assert.Equal(t, "web", risks[0].MostRelevantTechnicalAssetId)
}

func TestHttpRequestSmugglingNoRisksWithoutForwardingSourceOrOutOfScopeOrNonWebProtocol(t *testing.T) {
	web := func() *types.TechnicalAsset { return ptAsset("web", ptTech(types.WebServer, "web_application")) }
	proxy := func() *types.TechnicalAsset {
		return ptAsset("proxy", ptTech(types.ReverseProxy, types.IsTrafficForwarding))
	}
	client := ptAsset("client", ptTech(types.Browser))

	cases := map[string]*types.Model{
		"source is no forwarder": ptModel([]*types.TechnicalAsset{client, web()}, []*types.CommunicationLink{ptLink("l", "client", "web", types.HTTPS)}, nil),
		"non web protocol":       ptModel([]*types.TechnicalAsset{proxy(), web()}, []*types.CommunicationLink{ptLink("l", "proxy", "web", types.SSH)}, nil),
	}
	outOfScope := web()
	outOfScope.OutOfScope = true
	cases["target out of scope"] = ptModel([]*types.TechnicalAsset{proxy(), outOfScope}, []*types.CommunicationLink{ptLink("l", "proxy", "web", types.HTTPS)}, nil)

	for name, model := range cases {
		risks, err := NewHttpRequestSmugglingRule().GenerateRisks(model)
		assert.NoError(t, err, name)
		assert.Empty(t, risks, name)
	}
}
