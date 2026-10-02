package analyst

import (
	"encoding/json"
	"testing"
)

func TestApplySubmitValidation(t *testing.T) {
	var f Finding
	ok := `{"title":"t","summary":"s","classification":"suspicious","severity":"medium","confidence":1.4,
		"evidence":[{"claim":"c","source":"top_n"}],
		"recommendations":[{"type":"flowspec","title":"x","detail":"y","flowspec":{"target":"198.51.100.1","protocol":"udp","src_ports":[53]}}]}`
	if err := applySubmit(&f, json.RawMessage(ok)); err != nil {
		t.Fatal(err)
	}
	if f.Confidence != 1 {
		t.Errorf("confidence should be clamped to 1, got %v", f.Confidence)
	}
	bad := []string{
		`{"summary":"s","classification":"attack","severity":"high","confidence":0.5}`,
		`{"title":"t","summary":"s","classification":"maybe","severity":"high","confidence":0.5}`,
		`{"title":"t","summary":"s","classification":"attack","severity":"urgent","confidence":0.5}`,
		`{"title":"t","summary":"s","classification":"attack","severity":"high","confidence":0.5,"recommendations":[{"type":"flowspec","title":"x","detail":"y"}]}`,
		`{"title":"t","summary":"s","classification":"attack","severity":"high","confidence":0.5,"recommendations":[{"type":"delete_everything","title":"x","detail":"y"}]}`,
	}
	for i, b := range bad {
		var g Finding
		if applySubmit(&g, json.RawMessage(b)) == nil {
			t.Errorf("case %d should be rejected", i)
		}
	}
}

func TestToolSchemasAreObjects(t *testing.T) {
	for _, tool := range buildTools(nil, nil) {
		if tool.Name == "" || tool.Description == "" || tool.Properties == nil {
			t.Errorf("tool %q incomplete", tool.Name)
		}
		if _, err := json.Marshal(tool.Properties); err != nil {
			t.Errorf("tool %q schema not serializable: %v", tool.Name, err)
		}
	}
}
