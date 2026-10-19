package web

import (
	"context"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/stefanozanarini/open-rmm/internal/adinv"
	"github.com/stefanozanarini/open-rmm/internal/console/store"
)

// adCache keeps parsed Active Directory reports, which can hold thousands
// of computers, until a newer report arrives.
type adCache struct {
	mu sync.Mutex
	m  map[string]adCached // tenant/domain
}

type adCached struct {
	at   time.Time
	snap *adinv.Snapshot
}

// adSnapshots returns the tenant's domain reports.
func (s *Server) adSnapshots(ctx context.Context, t string) ([]*adinv.Snapshot, error) {
	doms, err := s.store.ListADDomains(ctx, t)
	if err != nil {
		return nil, err
	}
	s.ad.mu.Lock()
	defer s.ad.mu.Unlock()
	if s.ad.m == nil {
		s.ad.m = map[string]adCached{}
	}
	var out []*adinv.Snapshot
	for _, d := range doms {
		k := t + "/" + d.Domain
		if c, ok := s.ad.m[k]; ok && c.at.Equal(d.CollectedAt) {
			out = append(out, c.snap)
			continue
		}
		snap, err := adinv.Parse(d.Data)
		if err != nil {
			s.log.Warn("stored Active Directory report unreadable", "domain", d.Domain, "err", err)
			continue
		}
		s.ad.m[k] = adCached{at: d.CollectedAt, snap: snap}
		out = append(out, snap)
	}
	return out, nil
}

// adPlace is where an agent is in the directory.
type adPlace struct {
	Domain string
	adinv.Computer
}

// Key is the tree key of the agent's container: domain/OU path.
func (p adPlace) Key() string {
	if ou := p.OU(); ou != "" {
		return p.Domain + "/" + ou
	}
	return p.Domain
}

// adPlaces maps agent host keys to their computer objects.
func adPlaces(snaps []*adinv.Snapshot) map[string]adPlace {
	out := map[string]adPlace{}
	for _, s := range snaps {
		for _, c := range s.Computers {
			out[c.Name] = adPlace{Domain: s.Domain, Computer: c}
		}
	}
	return out
}

// inOU tells whether key is ou or below it.
func inOU(key, ou string) bool { return key == ou || strings.HasPrefix(key, ou+"/") }

// ouView is a node of the OU tree.
type ouView struct {
	Key, Label string
	Depth      int // for indentation, at most 4
	Count      int
}

// ouTree builds the tree of the containers holding agents, with counts that
// include sub-containers.
func ouTree(keys []string) []ouView {
	count := map[string]int{}
	for _, k := range keys {
		parts := strings.Split(k, "/")
		for i := range parts {
			count[strings.Join(parts[:i+1], "/")]++
		}
	}
	var out []ouView
	for k, n := range count {
		parts := strings.Split(k, "/")
		out = append(out, ouView{Key: k, Label: parts[len(parts)-1], Depth: min(len(parts)-1, 4), Count: n})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out
}

type adDomainView struct {
	adinv.Report
	Agent string // hostname of the reporting endpoint
}

type adData struct {
	Domains []adDomainView
	// AgentsOutside are Windows agents not found in any domain.
	AgentsOutside []store.Agent
	Now           time.Time
}

func (s *Server) handleAD(w http.ResponseWriter, r *http.Request) {
	t, ok := tenantOf(r)
	if !ok {
		http.Error(w, s.T(r, "nessun tenant"), http.StatusForbidden)
		return
	}
	snaps, err := s.adSnapshots(r.Context(), t)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	doms, err := s.store.ListADDomains(r.Context(), t)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	agents, err := s.store.ListAgents(r.Context(), t)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	now := s.now()
	keys := map[string]bool{}
	names := map[string]string{}
	for _, a := range agents {
		if a.Status == store.AgentRevoked {
			continue
		}
		keys[adinv.HostKey(a.Host.Hostname)] = true
		names[a.ID] = a.Host.Hostname
	}
	d := adData{Now: now}
	reporter := map[string]string{}
	for _, dm := range doms {
		reporter[dm.Domain] = names[dm.AgentID]
	}
	for _, sn := range snaps {
		d.Domains = append(d.Domains, adDomainView{Report: adinv.Analyze(sn, keys, now), Agent: reporter[sn.Domain]})
	}
	if len(snaps) > 0 {
		places := adPlaces(snaps)
		for _, a := range agents {
			if a.Status == store.AgentRevoked || a.Host.OS != "windows" {
				continue
			}
			if _, ok := places[adinv.HostKey(a.Host.Hostname)]; !ok {
				d.AgentsOutside = append(d.AgentsOutside, a)
			}
		}
	}
	s.render(w, r, "ad", s.T(r, "Active Directory"), d)
}
