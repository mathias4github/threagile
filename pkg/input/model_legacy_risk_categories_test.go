package input

import (
	"os"
	"path/filepath"
	"testing"
)

const legacyRiskCategoryYaml = `
individual_risk_categories:
  Some Individual Risk Example:
    id: something-strange
    description: Some text describing the risk category...
    function: business-side
    stride: repudiation
    cwe: 693
    risks_identified:
      <b>Example Individual Risk</b> at <b>Database</b>:
        severity: critical
        most_relevant_technical_asset: sql-database
`

func writeModel(t *testing.T, dir, name, content string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// Issue #130: the legacy key "individual_risk_categories" must still be read.
func TestLoadAcceptsLegacyIndividualRiskCategories(t *testing.T) {
	path := writeModel(t, t.TempDir(), "model.yaml", legacyRiskCategoryYaml)

	model := new(Model).Defaults()
	if err := model.Load(path); err != nil {
		t.Fatal(err)
	}

	if len(model.CustomRiskCategories) != 1 {
		t.Fatalf("expected 1 custom risk category, got %d", len(model.CustomRiskCategories))
	}
	category := model.CustomRiskCategories[0]
	if category.ID != "something-strange" {
		t.Errorf("unexpected id %q", category.ID)
	}
	if category.Title != "Some Individual Risk Example" {
		t.Errorf("legacy map key should become title, got %q", category.Title)
	}
	if len(category.RisksIdentified) != 1 {
		t.Errorf("expected 1 identified risk, got %d", len(category.RisksIdentified))
	}
}

func TestMergeAcceptsLegacyIndividualRiskCategories(t *testing.T) {
	dir := t.TempDir()
	writeModel(t, dir, "inc.yaml", legacyRiskCategoryYaml)
	path := writeModel(t, dir, "model.yaml", "includes:\n  - inc.yaml\n")

	model := new(Model).Defaults()
	if err := model.Load(path); err != nil {
		t.Fatal(err)
	}
	if len(model.CustomRiskCategories) != 1 {
		t.Fatalf("expected 1 custom risk category from include, got %d", len(model.CustomRiskCategories))
	}
}

func TestLoadCustomRiskCategoriesUnchanged(t *testing.T) {
	path := writeModel(t, t.TempDir(), "model.yaml", "custom_risk_categories:\n  - id: a\n    title: A\n")
	model := new(Model).Defaults()
	if err := model.Load(path); err != nil {
		t.Fatal(err)
	}
	if len(model.CustomRiskCategories) != 1 || model.CustomRiskCategories[0].ID != "a" {
		t.Fatalf("unexpected categories: %+v", model.CustomRiskCategories)
	}
}

// An include file carrying both the new and the legacy key must merge each category once.
func TestMergeIncludeWithBothRiskCategoryKeys(t *testing.T) {
	dir := t.TempDir()
	writeModel(t, dir, "inc.yaml", "custom_risk_categories:\n  - id: a\n    title: A\n"+legacyRiskCategoryYaml)

	model := new(Model).Defaults()
	if err := model.Merge(dir, "inc.yaml"); err != nil {
		t.Fatalf("merge failed: %v", err)
	}
	if len(model.CustomRiskCategories) != 2 {
		t.Fatalf("expected 2 custom risk categories, got %d", len(model.CustomRiskCategories))
	}
}
