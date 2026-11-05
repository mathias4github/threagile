package report

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/threagile/threagile/pkg/types"
)

// Issue #96: risks.json must carry the CWE of the risk category, like risks.xlsx does.
func TestWriteRisksJSONContainsCWE(t *testing.T) {
	model := &types.Model{
		BuiltInRiskCategories: types.RiskCategories{{ID: "with-cwe", CWE: 89}, {ID: "without-cwe"}},
		GeneratedRisksByCategory: map[string][]*types.Risk{
			"with-cwe":    {{CategoryId: "with-cwe", SyntheticId: "with-cwe@a", Title: "t1"}},
			"without-cwe": {{CategoryId: "without-cwe", SyntheticId: "without-cwe@a", Title: "t2"}},
		},
	}
	file := filepath.Join(t.TempDir(), "risks.json")
	if err := WriteRisksJSON(model, file); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}

	var risks []map[string]any
	if err = json.Unmarshal(data, &risks); err != nil {
		t.Fatal(err)
	}
	if len(risks) != 2 {
		t.Fatalf("expected 2 risks, got %d", len(risks))
	}
	for _, risk := range risks {
		switch risk["category"] {
		case "with-cwe":
			if risk["cwe"] != float64(89) {
				t.Errorf("expected cwe 89, got %v", risk["cwe"])
			}
		case "without-cwe":
			if _, present := risk["cwe"]; present {
				t.Errorf("risk without CWE must not carry a cwe field, got %v", risk["cwe"])
			}
		}
	}
}
