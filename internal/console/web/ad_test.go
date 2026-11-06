package web

import "testing"

func TestOUTreeKeepsEmptyContainers(t *testing.T) {
	all := []string{"corp/FR/FR01", "corp/FR/FR01", "corp/UK/UK01", "corp/UK/UK01"}
	got := map[string]int{}
	for _, o := range ouTree(all, []string{"corp/UK/UK01"}) {
		got[o.Key] = o.Count
	}
	want := map[string]int{"corp": 1, "corp/FR": 0, "corp/FR/FR01": 0, "corp/UK": 1, "corp/UK/UK01": 1}
	if len(got) != len(want) {
		t.Fatalf("tree = %v", got)
	}
	for k, n := range want {
		if c, ok := got[k]; !ok || c != n {
			t.Errorf("%s = %d (listed %v), want %d", k, c, ok, n)
		}
	}
}
