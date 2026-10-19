package accesslog

import "testing"

func TestParse(t *testing.T) {
	r, err := Parse([]byte(`{"events":[
	 {"channel":"security","record_id":10,"time":"2026-10-19T08:00:00Z","event_id":4624,"kind":"logon","user":"mario","logon_type":10,"source_ip":"::ffff:192.168.1.5"},
	 {"channel":"lsm","record_id":3,"time":"2026-10-19T08:00:01Z","event_id":21,"kind":"rdp_session_logon","user":"CORP\\mario","source_ip":"LOCAL"},
	 {"channel":"evil","record_id":1,"time":"2026-10-19T08:00:00Z","event_id":1,"kind":"logon"},
	 {"channel":"security","record_id":11,"time":"2026-10-19T08:00:00Z","event_id":4625,"kind":"other"},
	 {"channel":"security","record_id":12,"time":"2026-10-19T08:00:00Z","event_id":4625,"kind":"logon_failed","user":"-","source_ip":"-"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Events) != 3 {
		t.Fatalf("events = %+v", r.Events)
	}
	if r.Events[0].SourceIP != "192.168.1.5" || r.Events[1].SourceIP != "" || r.Events[2].User != "" {
		t.Fatalf("normalization: %+v", r.Events)
	}
}

func TestSubnets(t *testing.T) {
	p, err := ParseSubnets([]string{"192.168.10.0/24", " 10.1.2.3 ", ""})
	if err != nil || len(p) != 2 {
		t.Fatal(p, err)
	}
	if !Allowed("192.168.10.77", p) || !Allowed("10.1.2.3", p) || Allowed("10.1.2.4", p) || Allowed("x", p) {
		t.Fatal("Allowed")
	}
	if _, err := ParseSubnets([]string{"192.168.10.0/33"}); err == nil {
		t.Fatal("invalid prefix accepted")
	}
	if !Allowed("172.20.1.1", DefaultAllowed) || Allowed("8.8.8.8", DefaultAllowed) {
		t.Fatal("defaults")
	}
}

func TestIsRDP(t *testing.T) {
	if !IsRDP(KindLogon, 10) || IsRDP(KindLogon, 2) || !IsRDP(KindRDPAuth, 0) || IsRDP(KindLogonFailed, 10) {
		t.Fatal("IsRDP")
	}
}
