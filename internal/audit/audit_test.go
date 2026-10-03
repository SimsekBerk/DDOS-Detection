package audit

import (
	"fmt"
	"testing"
)

func TestRecordQueryAndReload(t *testing.T) {
	dir := t.TempDir()
	l, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	l.Record(Entry{User: "admin", Action: "config.update", Target: "config", OK: true})
	l.Record(Entry{User: "noc", Action: "mitigation.action", Target: "mitigations/M1/approve", OK: true})
	l.Record(Entry{User: "noc", Action: "auth.login", OK: false, Error: "kullanıcı adı veya parola hatalı"})
	if got := l.Query("", "", 10); len(got) != 3 || got[0].Action != "auth.login" {
		t.Fatalf("newest-first query = %+v", got)
	}
	if got := l.Query("noc", "mitigation", 10); len(got) != 1 || got[0].Target != "mitigations/M1/approve" {
		t.Fatalf("filtered query = %+v", got)
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	// Entries survive a restart and new ones are appended.
	l2, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer l2.Close()
	l2.Record(Entry{User: "admin", Action: "user.save"})
	got := l2.Query("", "", 10)
	if len(got) != 4 || got[0].Action != "user.save" || got[0].T == 0 {
		t.Fatalf("after reload = %+v", got)
	}
}

func TestRetentionBound(t *testing.T) {
	l, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	for i := 0; i < keep+50; i++ {
		l.Record(Entry{User: "u", Action: fmt.Sprintf("a.%d", i)})
	}
	if got := l.Query("", "", keep+100); len(got) != 200 {
		t.Fatalf("limit above keep should fall back to default 200, got %d", len(got))
	}
	got := l.Query("", "", keep)
	if len(got) != keep || got[len(got)-1].Action != "a.50" {
		t.Fatalf("in-memory window should hold the newest %d entries, oldest = %q", keep, got[len(got)-1].Action)
	}
}
