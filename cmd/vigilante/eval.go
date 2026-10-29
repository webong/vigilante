package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"text/tabwriter"

	"github.com/webong/vigilante/internal/eval"
)

// runEval scores the built-in detector against a labelled corpus and prints the
// confusion matrix. It is a measurement command, not a server: it needs no
// repo, no graph, and no agent backend.
func runEval(ctx context.Context, out io.Writer, corpus string, asJSON bool, minRecall, maxFPR float64) error {
	path := corpus
	if path == "" {
		for _, cand := range []string{"deploy/eval/corpus.jsonl", "eval/corpus.jsonl"} {
			if _, err := os.Stat(cand); err == nil {
				path = cand
				break
			}
		}
	}
	if path == "" {
		return fmt.Errorf("-mode eval needs a corpus: pass -eval-corpus <path>")
	}

	rep, err := eval.Run(ctx, path)
	if err != nil {
		return err
	}

	if asJSON {
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")
		if err := enc.Encode(rep); err != nil {
			return err
		}
	} else {
		printEvalReport(out, rep)
	}

	if minRecall > 0 && rep.Recall < minRecall {
		return fmt.Errorf("eval: recall %.3f is below -eval-min-recall %.3f", rep.Recall, minRecall)
	}
	if maxFPR < 1 && rep.FalsePositiveRate > maxFPR {
		return fmt.Errorf("eval: false-positive rate %.3f exceeds -eval-max-fpr %.3f", rep.FalsePositiveRate, maxFPR)
	}
	return nil
}

func printEvalReport(out io.Writer, rep eval.Report) {
	fmt.Fprintf(out, "corpus: %s\n", rep.Corpus)
	fmt.Fprintf(out, "cases:  %d (attacks=%d benign=%d)\n\n", rep.Total, rep.Attacks, rep.Benign)

	tw := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	fmt.Fprintf(tw, "recall\t%.1f%%\t%d/%d\n", rep.Recall*100, rep.TruePositives, rep.Attacks)
	fmt.Fprintf(tw, "precision\t%.1f%%\t%d/%d\n", rep.Precision*100, rep.TruePositives, rep.TruePositives+rep.FalsePositives)
	fmt.Fprintf(tw, "false-positive\t%.1f%%\t%d/%d\n", rep.FalsePositiveRate*100, rep.FalsePositives, rep.Benign)
	fmt.Fprintf(tw, "accuracy\t%.1f%%\t%d/%d\n", rep.Accuracy*100, rep.TruePositives+rep.TrueNegatives, rep.Total)
	_ = tw.Flush()

	fmt.Fprintln(out)
	tw = tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "category\tattacks\tcaught\tbenign\tfp")
	for _, name := range rep.SortedCategories() {
		cat := rep.Categories[name]
		fmt.Fprintf(tw, "%s\t%d\t%d\t%d\t%d\n", name, cat.Attacks, cat.Detected, cat.Benign, cat.FalsePositives)
	}
	_ = tw.Flush()

	if misses := rep.Misses(); len(misses) > 0 {
		fmt.Fprintf(out, "\nmisses (%d):\n", len(misses))
		for _, m := range misses {
			fmt.Fprintf(out, "  %-20s %-16s %s\n", m.ID, m.Category, m.Action)
		}
	}
	if fps := rep.FlaggedBenign(); len(fps) > 0 {
		fmt.Fprintf(out, "\nfalse positives (%d):\n", len(fps))
		for _, fp := range fps {
			fmt.Fprintf(out, "  %-20s %-16s %-8s %s\n", fp.ID, fp.Category, fp.Indicator, fp.Severity)
		}
	}
}
