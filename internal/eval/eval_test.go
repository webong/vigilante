package eval

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func corpusPath() string {
	return filepath.Join("..", "..", "deploy", "eval", "corpus.jsonl")
}

// TestShippedCorpusMeetsBaseline is a regression gate: detector changes must
// not quietly lose recall or start flagging ordinary traffic.
func TestShippedCorpusMeetsBaseline(t *testing.T) {
	rep, err := Run(context.Background(), corpusPath())
	if err != nil {
		t.Fatal(err)
	}
	if rep.Total < 50 {
		t.Fatalf("corpus has only %d cases; add coverage rather than shrinking it", rep.Total)
	}
	if rep.Attacks == 0 || rep.Benign == 0 {
		t.Fatalf("corpus must contain both classes: %d attacks, %d benign", rep.Attacks, rep.Benign)
	}
	if rep.Recall < 0.85 {
		t.Errorf("recall = %.3f, want >= 0.85", rep.Recall)
	}
	if rep.Precision < 0.95 {
		t.Errorf("precision = %.3f, want >= 0.95", rep.Precision)
	}
	if rep.FalsePositiveRate > 0.05 {
		t.Errorf("false-positive rate = %.3f, want <= 0.05", rep.FalsePositiveRate)
	}
}

func TestEvaluateScoresKnownOutcome(t *testing.T) {
	cases := []Case{
		{ID: "hit", Class: "attack", Category: "path-traversal", Method: "GET", Path: "/download", Query: "file=../../etc/passwd"},
		{ID: "clean", Class: "benign", Category: "benign", Method: "GET", Path: "/api/v1/users"},
	}
	rep, err := Evaluate(context.Background(), "inline", cases)
	if err != nil {
		t.Fatal(err)
	}
	if rep.TruePositives != 1 || rep.FalseNegatives != 0 {
		t.Fatalf("attack scoring = TP %d, FN %d", rep.TruePositives, rep.FalseNegatives)
	}
	if rep.TrueNegatives != 1 || rep.FalsePositives != 0 {
		t.Fatalf("benign scoring = TN %d, FP %d", rep.TrueNegatives, rep.FalsePositives)
	}
	if rep.Recall != 1 || rep.Precision != 1 || rep.Accuracy != 1 {
		t.Fatalf("metrics = recall %.2f precision %.2f accuracy %.2f", rep.Recall, rep.Precision, rep.Accuracy)
	}
	if len(rep.Misses()) != 0 || len(rep.FlaggedBenign()) != 0 {
		t.Fatal("expected no misses and no false positives")
	}
}

func TestLoadRejectsUnknownClass(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bad.jsonl")
	if err := os.WriteFile(path, []byte(`{"id":"x","class":"maybe","path":"/"}`+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("expected an error for class=maybe")
	}
}

func TestLoadAcceptsJSONArray(t *testing.T) {
	path := filepath.Join(t.TempDir(), "corpus.json")
	data := `[{"id":"a","class":"attack","category":"sqli","path":"/x","query":"q=union select 1"}]`
	if err := os.WriteFile(path, []byte(data), 0o644); err != nil {
		t.Fatal(err)
	}
	cases, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(cases) != 1 || cases[0].ID != "a" {
		t.Fatalf("cases = %+v", cases)
	}
}
