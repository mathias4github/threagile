package builtin

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/threagile/threagile/pkg/types"
)

func proposedRules() []types.RiskRule {
	return []types.RiskRule{
		NewMissingBruteForceProtectionRule(), NewMissingAuthorizationRule(), NewMissingMonitoringRule(), NewSensitiveDataInLogsRule(),
		NewMissingRedundancyRule(), NewInternetExposedDatastoreRule(), NewWeakSessionManagementRule(), NewOsCommandInjectionRule(),
		NewHardcodedCredentialsRule(), NewLlmExcessiveAgencyRule(),
	}
}

func TestProposedRulesEmptyModelCreatesNoRisks(t *testing.T) {
	for _, rule := range proposedRules() {
		risks, err := rule.GenerateRisks(&types.Model{})
		assert.NoError(t, err, rule.Category().ID)
		assert.Empty(t, risks, rule.Category().ID)
	}
}

func TestProposedRulesHaveCompleteCategories(t *testing.T) {
	for _, rule := range proposedRules() {
		category := rule.Category()
		assert.NotEmpty(t, category.ID)
		assert.NotEmpty(t, category.Title)
		assert.NotEmpty(t, category.Description)
		assert.NotEmpty(t, category.Mitigation)
		assert.NotEmpty(t, category.DetectionLogic)
		assert.Regexp(t, `^V[0-9]+ - `, category.ASVS, category.ID)
		assert.Regexp(t, `^https://`, category.CheatSheet, category.ID)
		assert.Greater(t, category.CWE, 0, category.ID)
	}
}

// --- missing-brute-force-protection ---

func TestMissingBruteForceProtectionInternetCredentialsLoginCreatesLikelyRisk(t *testing.T) {
	client := ptAsset("client", ptTech(types.Browser))
	client.Internet = true
	app := ptAsset("app", ptTech(types.WebApplication))
	link := ptLink("login", "client", "app", types.HTTPS)
	link.Authentication = types.Credentials

	risks, err := NewMissingBruteForceProtectionRule().GenerateRisks(ptModel([]*types.TechnicalAsset{client, app}, []*types.CommunicationLink{link}, nil))

	require.NoError(t, err)
	require.Len(t, risks, 1)
	assert.Equal(t, "missing-brute-force-protection@client@app@login", risks[0].SyntheticId)
	assert.Equal(t, types.Likely, risks[0].ExploitationLikelihood)
}

func TestMissingBruteForceProtectionNoRiskForTokenAuthOrInternalTechnicalCaller(t *testing.T) {
	build := func(auth types.Authentication, internet bool, human bool) *types.Model {
		client := ptAsset("client", ptTech(types.WebApplication))
		client.Internet, client.UsedAsClientByHuman = internet, human
		app := ptAsset("app", ptTech(types.WebApplication))
		link := ptLink("l", "client", "app", types.HTTPS)
		link.Authentication = auth
		return ptModel([]*types.TechnicalAsset{client, app}, []*types.CommunicationLink{link}, nil)
	}
	for name, model := range map[string]*types.Model{
		"token from internet":        build(types.Token, true, false),
		"credentials internal":       build(types.Credentials, false, false),
		"client cert human operated": build(types.ClientCertificate, false, true),
	} {
		risks, err := NewMissingBruteForceProtectionRule().GenerateRisks(model)
		assert.NoError(t, err, name)
		assert.Empty(t, risks, name)
	}
	risks, _ := NewMissingBruteForceProtectionRule().GenerateRisks(build(types.Credentials, false, true))
	require.Len(t, risks, 1, "human client with credentials")
	assert.Equal(t, types.Unlikely, risks[0].ExploitationLikelihood)
}

// --- missing-authorization ---

func authorizationModel(targetTech *types.Technology, auth types.Authentication, authz types.Authorization, sensitive bool) *types.Model {
	app := ptAsset("app", ptTech(types.WebApplication))
	target := ptAsset("target", targetTech)
	link := ptLink("l", "app", "target", types.JdbcEncrypted)
	link.Authentication, link.Authorization = auth, authz
	model := ptModel([]*types.TechnicalAsset{app, target}, []*types.CommunicationLink{link}, nil)
	if sensitive {
		ptProcess(model, target, types.Confidential, types.Operational)
	}
	return model
}

func TestMissingAuthorizationAuthenticatedUnauthorizedAccessToSensitiveDatastoreCreatesRisk(t *testing.T) {
	risks, err := NewMissingAuthorizationRule().GenerateRisks(authorizationModel(ptTech(types.Database), types.Credentials, types.NoneAuthorization, true))

	require.NoError(t, err)
	require.Len(t, risks, 1)
	assert.Equal(t, "missing-authorization@app@target@l", risks[0].SyntheticId)
}

func TestMissingAuthorizationNoRiskWhenAuthorizedUnauthenticatedInsensitiveOrEndUserFacing(t *testing.T) {
	for name, model := range map[string]*types.Model{
		"authorized":        authorizationModel(ptTech(types.Database), types.Credentials, types.TechnicalUser, true),
		"no authentication": authorizationModel(ptTech(types.Database), types.NoneAuthentication, types.NoneAuthorization, true),
		"not sensitive":     authorizationModel(ptTech(types.Database), types.Credentials, types.NoneAuthorization, false),
		"end user facing":   authorizationModel(ptTech(types.WebApplication, types.IsUsuallyProcessingEndUserRequests), types.Credentials, types.NoneAuthorization, true),
	} {
		risks, err := NewMissingAuthorizationRule().GenerateRisks(model)
		assert.NoError(t, err, name)
		assert.Empty(t, risks, name)
	}
}

// --- missing-monitoring ---

func TestMissingMonitoringSensitiveModelWithoutMonitoringCreatesOneRisk(t *testing.T) {
	a := ptAsset("a", ptTech(types.WebApplication))
	b := ptAsset("b", ptTech(types.Database))
	model := ptModel([]*types.TechnicalAsset{a, b}, nil, nil)
	ptProcess(model, a, types.Confidential, types.Operational)
	ptProcess(model, b, types.StrictlyConfidential, types.MissionCritical)

	risks, err := NewMissingMonitoringRule().GenerateRisks(model)

	require.NoError(t, err)
	require.Len(t, risks, 1)
	assert.Equal(t, "missing-monitoring@b", risks[0].SyntheticId, "most sensitive asset is referenced")
	assert.Equal(t, types.HighImpact, risks[0].ExploitationImpact)
}

func TestMissingMonitoringNoRiskWithMonitoringAssetOrWithoutSensitiveAssets(t *testing.T) {
	a := ptAsset("a", ptTech(types.WebApplication))
	ids := ptAsset("ids", ptTech(types.IDS))
	model := ptModel([]*types.TechnicalAsset{a, ids}, nil, nil)
	ptProcess(model, a, types.StrictlyConfidential, types.Operational)
	risks, err := NewMissingMonitoringRule().GenerateRisks(model)
	require.NoError(t, err)
	assert.Empty(t, risks, "ids present")

	plain := ptAsset("a", ptTech(types.WebApplication))
	model = ptModel([]*types.TechnicalAsset{plain}, nil, nil)
	ptProcess(model, plain, types.Internal, types.Operational)
	risks, err = NewMissingMonitoringRule().GenerateRisks(model)
	require.NoError(t, err)
	assert.Empty(t, risks, "nothing sensitive")
}

// --- sensitive-data-in-logs ---

func TestSensitiveDataInLogsMonitoringWithConfidentialDataCreatesRisk(t *testing.T) {
	log := ptAsset("log", ptTech(types.Monitoring))
	model := ptModel([]*types.TechnicalAsset{log}, nil, nil)
	ptProcess(model, log, types.StrictlyConfidential, types.Operational)

	risks, err := NewSensitiveDataInLogsRule().GenerateRisks(model)

	require.NoError(t, err)
	require.Len(t, risks, 1)
	assert.Equal(t, types.HighImpact, risks[0].ExploitationImpact)
	assert.Equal(t, types.Probable, risks[0].DataBreachProbability)
}

func TestSensitiveDataInLogsNoRiskForInternalDataOrNonMonitoring(t *testing.T) {
	log := ptAsset("log", ptTech(types.Monitoring))
	model := ptModel([]*types.TechnicalAsset{log}, nil, nil)
	ptProcess(model, log, types.Internal, types.Operational)
	risks, _ := NewSensitiveDataInLogsRule().GenerateRisks(model)
	assert.Empty(t, risks, "internal data")

	db := ptAsset("db", ptTech(types.Database))
	model = ptModel([]*types.TechnicalAsset{db}, nil, nil)
	ptProcess(model, db, types.StrictlyConfidential, types.Operational)
	risks, _ = NewSensitiveDataInLogsRule().GenerateRisks(model)
	assert.Empty(t, risks, "not monitoring")
}

// --- missing-redundancy ---

func TestMissingRedundancyMissionCriticalSingleInstanceCreatesRisk(t *testing.T) {
	app := ptAsset("app", ptTech(types.WebApplication))
	app.Availability = types.MissionCritical

	risks, err := NewMissingRedundancyRule().GenerateRisks(ptModel([]*types.TechnicalAsset{app}, nil, nil))

	require.NoError(t, err)
	require.Len(t, risks, 1)
	assert.Equal(t, "missing-redundancy@app", risks[0].SyntheticId)
}

func TestMissingRedundancyNoRiskWhenRedundantLowerAvailabilityOrClient(t *testing.T) {
	redundant := ptAsset("app", ptTech(types.WebApplication))
	redundant.Availability, redundant.Redundant = types.MissionCritical, true
	critical := ptAsset("app", ptTech(types.WebApplication))
	critical.Availability = types.Critical
	client := ptAsset("app", ptTech(types.MobileApp, types.IsClient))
	client.Availability = types.MissionCritical
	for name, asset := range map[string]*types.TechnicalAsset{"redundant": redundant, "only critical": critical, "client": client} {
		risks, err := NewMissingRedundancyRule().GenerateRisks(ptModel([]*types.TechnicalAsset{asset}, nil, nil))
		assert.NoError(t, err, name)
		assert.Empty(t, risks, name)
	}
}

// --- internet-exposed-datastore ---

func TestInternetExposedDatastoreWithConfidentialDataCreatesRisk(t *testing.T) {
	store := ptAsset("bucket", ptTech(types.FileServer))
	store.Type, store.Internet = types.Datastore, true
	model := ptModel([]*types.TechnicalAsset{store}, nil, nil)
	ptProcess(model, store, types.StrictlyConfidential, types.Operational)
	store.DataAssetsStored = append(store.DataAssetsStored, "da-bucket")

	risks, err := NewInternetExposedDatastoreRule().GenerateRisks(model)

	require.NoError(t, err)
	require.Len(t, risks, 1)
	assert.Equal(t, types.HighImpact, risks[0].ExploitationImpact)
}

func TestInternetExposedDatastoreNoRiskWhenNotInternetNotDatastoreOrPublicData(t *testing.T) {
	build := func(assetType types.TechnicalAssetType, internet bool, confidentiality types.Confidentiality) *types.Model {
		store := ptAsset("bucket", ptTech(types.FileServer))
		store.Type, store.Internet = assetType, internet
		model := ptModel([]*types.TechnicalAsset{store}, nil, nil)
		ptProcess(model, store, confidentiality, types.Operational)
		store.DataAssetsStored = append(store.DataAssetsStored, "da-bucket")
		return model
	}
	for name, model := range map[string]*types.Model{
		"not internet":  build(types.Datastore, false, types.StrictlyConfidential),
		"not datastore": build(types.Process, true, types.StrictlyConfidential),
		"public data":   build(types.Datastore, true, types.Public),
	} {
		risks, err := NewInternetExposedDatastoreRule().GenerateRisks(model)
		assert.NoError(t, err, name)
		assert.Empty(t, risks, name)
	}
}

// --- weak-session-management ---

func TestWeakSessionManagementTaggedWebAssetUsedByHumansCreatesRisk(t *testing.T) {
	browser := ptAsset("browser", ptTech(types.Browser))
	browser.UsedAsClientByHuman = true
	web := ptAsset("web", ptTech(types.WebApplication))
	web.Tags = []string{"Session-Tokens"}

	risks, err := NewWeakSessionManagementRule().GenerateRisks(ptModel([]*types.TechnicalAsset{browser, web}, []*types.CommunicationLink{ptLink("l", "browser", "web", types.HTTPS)}, nil))

	require.NoError(t, err)
	require.Len(t, risks, 1)
	assert.Equal(t, "weak-session-management@web", risks[0].SyntheticId)
}

func TestWeakSessionManagementNoRiskWithoutTagOrHumanClient(t *testing.T) {
	browser := ptAsset("browser", ptTech(types.Browser))
	browser.UsedAsClientByHuman = true
	untagged := ptAsset("web", ptTech(types.WebApplication))
	risks, _ := NewWeakSessionManagementRule().GenerateRisks(ptModel([]*types.TechnicalAsset{browser, untagged}, []*types.CommunicationLink{ptLink("l", "browser", "web", types.HTTPS)}, nil))
	assert.Empty(t, risks, "no tag")

	service := ptAsset("svc", ptTech(types.WebServiceREST))
	tagged := ptAsset("web", ptTech(types.WebApplication))
	tagged.Tags = []string{"session-tokens"}
	risks, _ = NewWeakSessionManagementRule().GenerateRisks(ptModel([]*types.TechnicalAsset{service, tagged}, []*types.CommunicationLink{ptLink("l", "svc", "web", types.HTTPS)}, nil))
	assert.Empty(t, risks, "no human client")
}

// --- os-command-injection ---

func TestOsCommandInjectionTaggedCustomAssetCalledFromInternetCreatesRisk(t *testing.T) {
	client := ptAsset("client", ptTech(types.Browser))
	client.Internet = true
	app := ptAsset("app", ptTech(types.WebApplication))
	app.CustomDevelopedParts = true
	app.Tags = []string{"executes-os-commands"}

	risks, err := NewOsCommandInjectionRule().GenerateRisks(ptModel([]*types.TechnicalAsset{client, app}, []*types.CommunicationLink{ptLink("l", "client", "app", types.HTTPS)}, nil))

	require.NoError(t, err)
	require.Len(t, risks, 1)
	assert.Equal(t, types.MediumImpact, risks[0].ExploitationImpact, "impact is at least medium")
}

func TestOsCommandInjectionNoRiskWithoutTagCustomCodeOrUntrustedCaller(t *testing.T) {
	build := func(tagged bool, custom bool, internet bool) *types.Model {
		client := ptAsset("client", ptTech(types.WebApplication))
		client.Internet = internet
		app := ptAsset("app", ptTech(types.WebApplication))
		app.CustomDevelopedParts = custom
		if tagged {
			app.Tags = []string{"executes-os-commands"}
		}
		return ptModel([]*types.TechnicalAsset{client, app}, []*types.CommunicationLink{ptLink("l", "client", "app", types.HTTPS)}, nil)
	}
	for name, model := range map[string]*types.Model{
		"no tag": build(false, true, true), "third party": build(true, false, true), "trusted caller": build(true, true, false),
	} {
		risks, err := NewOsCommandInjectionRule().GenerateRisks(model)
		assert.NoError(t, err, name)
		assert.Empty(t, risks, name)
	}
}

// --- hardcoded-credentials ---

func TestHardcodedCredentialsTaggedDataAssetCreatesRiskReferencingHolder(t *testing.T) {
	app := ptAsset("app", ptTech(types.WebApplication))
	store := ptAsset("store", ptTech(types.Database))
	model := ptModel([]*types.TechnicalAsset{app, store}, nil, nil)
	ptProcess(model, app, types.Confidential, types.Operational)
	secret := model.DataAssets["da-app"]
	secret.Tags = []string{"credentials-hardcoded"}
	store.DataAssetsStored = []string{secret.Id}

	risks, err := NewHardcodedCredentialsRule().GenerateRisks(model)

	require.NoError(t, err)
	require.Len(t, risks, 1)
	assert.Equal(t, "hardcoded-credentials@da-app", risks[0].SyntheticId)
	assert.Equal(t, "store", risks[0].MostRelevantTechnicalAssetId, "storing asset preferred over processing asset")
	assert.Equal(t, "da-app", risks[0].MostRelevantDataAssetId)
	assert.Equal(t, types.HighImpact, risks[0].ExploitationImpact)
}

func TestHardcodedCredentialsNoRiskWithoutTagOrWithoutInScopeHolder(t *testing.T) {
	app := ptAsset("app", ptTech(types.WebApplication))
	model := ptModel([]*types.TechnicalAsset{app}, nil, nil)
	ptProcess(model, app, types.Confidential, types.Operational)
	risks, _ := NewHardcodedCredentialsRule().GenerateRisks(model)
	assert.Empty(t, risks, "no tag")

	app.OutOfScope = true
	model.DataAssets["da-app"].Tags = []string{"credentials-hardcoded"}
	risks, _ = NewHardcodedCredentialsRule().GenerateRisks(model)
	assert.Empty(t, risks, "holder out of scope")
}

// --- llm-excessive-agency ---

func TestLlmExcessiveAgencyAgentReachingCriticalSystemCreatesRisk(t *testing.T) {
	agent := ptAsset("agent", ptTech(types.AI))
	agent.Tags = []string{"ai-agent"}
	erp := ptAsset("erp", ptTech(types.ERP))
	erp.Integrity = types.MissionCritical
	model := ptModel([]*types.TechnicalAsset{agent, erp}, []*types.CommunicationLink{ptLink("l", "agent", "erp", types.HTTPS)}, nil)

	risks, err := NewLlmExcessiveAgencyRule().GenerateRisks(model)

	require.NoError(t, err)
	require.Len(t, risks, 1)
	assert.Equal(t, types.MediumImpact, risks[0].ExploitationImpact)
}

func TestLlmExcessiveAgencyCodeExecutionCreatesHighImpactRisk(t *testing.T) {
	agent := ptAsset("agent", ptTech(types.AI))
	agent.Tags = []string{"executes-code"}

	risks, err := NewLlmExcessiveAgencyRule().GenerateRisks(ptModel([]*types.TechnicalAsset{agent}, nil, nil))

	require.NoError(t, err)
	require.Len(t, risks, 1)
	assert.Equal(t, types.HighImpact, risks[0].ExploitationImpact)
}

func TestLlmExcessiveAgencyNoRiskForUntaggedOrAgentReachingOnlyLowIntegrity(t *testing.T) {
	untagged := ptAsset("agent", ptTech(types.AI))
	erp := ptAsset("erp", ptTech(types.ERP))
	erp.Integrity = types.MissionCritical
	risks, _ := NewLlmExcessiveAgencyRule().GenerateRisks(ptModel([]*types.TechnicalAsset{untagged, erp}, []*types.CommunicationLink{ptLink("l", "agent", "erp", types.HTTPS)}, nil))
	assert.Empty(t, risks, "no tag")

	agent := ptAsset("agent", ptTech(types.AI))
	agent.Tags = []string{"ai-agent"}
	wiki := ptAsset("wiki", ptTech(types.CMS))
	wiki.Integrity = types.Operational
	risks, _ = NewLlmExcessiveAgencyRule().GenerateRisks(ptModel([]*types.TechnicalAsset{agent, wiki}, []*types.CommunicationLink{ptLink("l", "agent", "wiki", types.HTTPS)}, nil))
	assert.Empty(t, risks, "only low-integrity targets")
}

// Callers that are out of scope (typically browsers and external clients) are still the attack path:
// the rules protect the in-scope target, so an out-of-scope caller must not suppress the risk.
func TestProposedRulesOutOfScopeCallerStillCreatesRisk(t *testing.T) {
	client := ptAsset("client", ptTech(types.Browser))
	client.Internet, client.UsedAsClientByHuman, client.OutOfScope = true, true, true
	app := ptAsset("app", ptTech(types.WebApplication))
	app.CustomDevelopedParts = true
	app.Tags = []string{"session-tokens", "executes-os-commands"}
	link := ptLink("login", "client", "app", types.HTTPS)
	link.Authentication = types.Credentials
	model := ptModel([]*types.TechnicalAsset{client, app}, []*types.CommunicationLink{link}, nil)

	for _, rule := range []types.RiskRule{NewMissingBruteForceProtectionRule(), NewWeakSessionManagementRule(), NewOsCommandInjectionRule()} {
		risks, err := rule.GenerateRisks(model)
		assert.NoError(t, err, rule.Category().ID)
		assert.Len(t, risks, 1, rule.Category().ID)
	}
}
