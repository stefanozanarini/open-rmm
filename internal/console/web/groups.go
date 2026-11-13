package web

import (
	"errors"
	"net/http"
	"net/url"
	"slices"
	"sort"
	"strings"
	"unicode"

	"github.com/stefanozanarini/tempra-rmm/internal/console/store"
	"github.com/stefanozanarini/tempra-rmm/internal/ids"
)

// Groups of computers or users: they filter the agent list and open the
// bulk actions on their computers. A user group stands for the computers
// where its users are logged on, or were last seen (userFor).

const (
	maxGroupMembers = 5000
	maxGroupName    = 64
	maxUserName     = 256
)

// groupView is a group in a list, with the computers it stands for.
type groupView struct {
	store.Group
	Computers int
	Personal  bool
}

type groupsData struct {
	Personal, Public []groupView
}

// groupMember is a row of a group page: a computer of a computer group,
// or a user of a user group with the computers where it was seen.
type groupMember struct {
	Member  string // agent id or user name
	Label   string // host name or user name
	Missing bool   // the agent does not exist anymore
	Agents  []groupAgent
}

type groupAgent struct {
	store.Agent
	Online bool
	User   userView
}

type groupData struct {
	groupView
	Members []groupMember
	// Active: the approved computers the bulk actions run on.
	Active  int
	Unknown string // names not added, from the last add
}

// groupMatcher tells whether an agent, with the user shown for it, is in
// a group.
type groupMatcher struct {
	kind  string
	ids   map[string]bool
	users []string // lower case
}

func newGroupMatcher(g store.Group) groupMatcher {
	m := groupMatcher{kind: g.Kind, ids: map[string]bool{}}
	for _, x := range g.Members {
		if g.Kind == store.GroupComputer {
			m.ids[x] = true
		} else {
			m.users = append(m.users, strings.ToLower(x))
		}
	}
	return m
}

func (m groupMatcher) has(agentID, user string) bool {
	if m.kind == store.GroupComputer {
		return m.ids[agentID]
	}
	for _, u := range m.users {
		if userMatches(u, user) {
			return true
		}
	}
	return false
}

// userMatches compares a group member with the user of a computer, both in
// lower case: DOMAIN\user and user@domain match exactly, a bare name
// matches the account name in any domain.
func userMatches(member, user string) bool {
	user = strings.ToLower(user)
	if member == "" || user == "" {
		return false
	}
	if member == user {
		return true
	}
	if strings.ContainsAny(member, `\@`) {
		return false
	}
	if _, name, ok := strings.Cut(user, `\`); ok {
		return member == name
	}
	name, _, _ := strings.Cut(user, "@")
	return member == name
}

// visibleGroups returns the public groups and the personal ones of the
// operator, by id.
func (s *Server) visibleGroups(r *http.Request, t string) ([]store.Group, error) {
	all, err := s.store.ListGroups(r.Context(), t)
	if err != nil {
		return nil, err
	}
	me := sessionFrom(r.Context()).data.Operator.Username
	return slices.DeleteFunc(all, func(g store.Group) bool { return g.Owner != "" && g.Owner != me }), nil
}

// findGroup returns a group the operator can see.
func (s *Server) findGroup(r *http.Request, t, id string) (store.Group, error) {
	if !ids.IsUUID(id) {
		return store.Group{}, store.ErrNotFound
	}
	groups, err := s.visibleGroups(r, t)
	if err != nil {
		return store.Group{}, err
	}
	for _, g := range groups {
		if g.ID == id {
			return g, nil
		}
	}
	return store.Group{}, store.ErrNotFound
}

// tenantAgents is every agent of a tenant with the user shown for it.
func (s *Server) tenantAgents(r *http.Request, t string) ([]groupAgent, error) {
	agents, err := s.store.ListAgents(r.Context(), t)
	if err != nil {
		return nil, err
	}
	sums, err := s.store.InventorySummaries(r.Context(), t)
	if err != nil {
		return nil, err
	}
	lastUsers, ttl := s.lastUsers(r.Context(), t)
	out := make([]groupAgent, 0, len(agents))
	for _, a := range agents {
		lu, has := lastUsers[a.ID]
		out = append(out, groupAgent{Agent: a, Online: s.online(a), User: s.userFor(a, sums[a.ID], lu, has, ttl)})
	}
	sort.Slice(out, func(i, j int) bool {
		return strings.ToLower(out[i].Host.Hostname) < strings.ToLower(out[j].Host.Hostname)
	})
	return out, nil
}

// groupAgents returns the agents a group stands for.
func groupAgents(g store.Group, all []groupAgent) []groupAgent {
	m := newGroupMatcher(g)
	var out []groupAgent
	for _, a := range all {
		if m.has(a.ID, a.User.Name) {
			out = append(out, a)
		}
	}
	return out
}

// activeIDs returns the ids of the approved agents.
func activeIDs(agents []groupAgent) []string {
	var out []string
	for _, a := range agents {
		if a.Status == store.AgentActive {
			out = append(out, a.ID)
		}
	}
	return out
}

func (s *Server) handleGroups(w http.ResponseWriter, r *http.Request) {
	t, ok := tenantOf(r)
	if !ok {
		http.Error(w, s.T(r, "nessun tenant"), http.StatusForbidden)
		return
	}
	groups, err := s.visibleGroups(r, t)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	all, err := s.tenantAgents(r, t)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	var d groupsData
	for _, g := range groups {
		v := groupView{Group: g, Computers: len(groupAgents(g, all)), Personal: g.Owner != ""}
		if v.Personal {
			d.Personal = append(d.Personal, v)
		} else {
			d.Public = append(d.Public, v)
		}
	}
	s.render(w, r, "groups", s.T(r, "Gruppi"), d)
}

func (s *Server) handleGroup(w http.ResponseWriter, r *http.Request) {
	t, ok := tenantOf(r)
	if !ok {
		http.Error(w, s.T(r, "nessun tenant"), http.StatusForbidden)
		return
	}
	g, err := s.findGroup(r, t, r.PathValue("id"))
	if errors.Is(err, store.ErrNotFound) {
		http.NotFound(w, r)
		return
	}
	if err != nil {
		s.fail(w, r, err)
		return
	}
	all, err := s.tenantAgents(r, t)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	members := groupAgents(g, all)
	d := groupData{groupView: groupView{Group: g, Computers: len(members), Personal: g.Owner != ""},
		Active: len(activeIDs(members)), Unknown: r.URL.Query().Get("unknown")}
	if g.Kind == store.GroupComputer {
		byID := map[string]groupAgent{}
		for _, a := range members {
			byID[a.ID] = a
		}
		for _, a := range members {
			d.Members = append(d.Members, groupMember{Member: a.ID, Label: a.Host.Hostname, Agents: []groupAgent{a}})
		}
		for _, id := range g.Members {
			if _, ok := byID[id]; !ok {
				d.Members = append(d.Members, groupMember{Member: id, Label: id, Missing: true})
			}
		}
	} else {
		for _, u := range g.Members {
			m := groupMember{Member: u, Label: u}
			for _, a := range members {
				if userMatches(strings.ToLower(u), a.User.Name) {
					m.Agents = append(m.Agents, a)
				}
			}
			d.Members = append(d.Members, m)
		}
	}
	s.render(w, r, "group", g.Name, d)
}

// groupName validates a group name.
func groupName(s string) (string, bool) {
	s = strings.TrimSpace(s)
	return s, s != "" && len(s) <= maxGroupName && !strings.ContainsFunc(s, unicode.IsControl)
}

// handleCreateGroup creates a group, with the computers in the "agent"
// values when it comes from the bulk actions.
func (s *Server) handleCreateGroup(w http.ResponseWriter, r *http.Request) {
	t, ok := tenantOf(r)
	if !ok {
		http.Error(w, s.T(r, "nessun tenant"), http.StatusForbidden)
		return
	}
	op := sessionFrom(r.Context()).data.Operator
	name, ok := groupName(r.PostFormValue("name"))
	if !ok {
		s.flash(w, r, s.Tf(r, "Nome del gruppo non valido (al massimo %d caratteri).", maxGroupName), "/groups")
		return
	}
	g := store.Group{TenantID: t, ID: ids.NewUUID(), Name: name, Kind: r.PostFormValue("kind"), CreatedBy: op.Username}
	if g.Kind != store.GroupComputer && g.Kind != store.GroupUser {
		http.Error(w, s.T(r, "richiesta non valida"), http.StatusBadRequest)
		return
	}
	if r.PostFormValue("scope") != "public" {
		g.Owner = op.Username
	}
	agents := validIDs(r.PostForm["agent"])
	if len(agents) > 0 && g.Kind != store.GroupComputer {
		http.Error(w, s.T(r, "richiesta non valida"), http.StatusBadRequest)
		return
	}
	switch err := s.store.PutGroup(r.Context(), g); {
	case errors.Is(err, store.ErrGroupExists):
		s.flash(w, r, s.T(r, "Esiste già un gruppo con questo nome."), "/groups")
		return
	case err != nil:
		s.fail(w, r, err)
		return
	}
	s.audit(r.Context(), t, op, "group.created", g.ID, map[string]any{"name": name, "kind": g.Kind, "personal": g.Owner != ""})
	if len(agents) > 0 {
		if err := s.addGroupMembers(r, t, g, agents); err != nil {
			s.fail(w, r, err)
			return
		}
	}
	s.flash(w, r, s.Tf(r, "Gruppo %s creato.", name), "/groups/"+g.ID)
}

// validIDs keeps the distinct UUIDs.
func validIDs(values []string) []string {
	var out []string
	for _, v := range values {
		if ids.IsUUID(v) && !slices.Contains(out, v) {
			out = append(out, v)
		}
	}
	return out
}

func (s *Server) addGroupMembers(r *http.Request, t string, g store.Group, members []string) error {
	if err := s.store.AddGroupMembers(r.Context(), t, g.ID, members); err != nil {
		return err
	}
	s.audit(r.Context(), t, sessionFrom(r.Context()).data.Operator, "group.members_added", g.ID, map[string]any{"members": members})
	return nil
}

// handleEditGroup renames or deletes a group, or adds and removes members.
func (s *Server) handleEditGroup(w http.ResponseWriter, r *http.Request) {
	t, ok := tenantOf(r)
	if !ok {
		http.Error(w, s.T(r, "nessun tenant"), http.StatusForbidden)
		return
	}
	g, err := s.findGroup(r, t, r.PathValue("id"))
	if errors.Is(err, store.ErrNotFound) {
		http.NotFound(w, r)
		return
	}
	if err != nil {
		s.fail(w, r, err)
		return
	}
	op := sessionFrom(r.Context()).data.Operator
	back := "/groups/" + g.ID
	switch r.PostFormValue("do") {
	case "rename":
		name, ok := groupName(r.PostFormValue("name"))
		if !ok {
			s.flash(w, r, s.Tf(r, "Nome del gruppo non valido (al massimo %d caratteri).", maxGroupName), back)
			return
		}
		g.Name = name
		switch err := s.store.PutGroup(r.Context(), g); {
		case errors.Is(err, store.ErrGroupExists):
			s.flash(w, r, s.T(r, "Esiste già un gruppo con questo nome."), back)
			return
		case err != nil:
			s.fail(w, r, err)
			return
		}
		s.audit(r.Context(), t, op, "group.renamed", g.ID, map[string]any{"name": name})
		s.flash(w, r, s.T(r, "Gruppo rinominato."), back)
	case "delete":
		if err := s.store.DeleteGroup(r.Context(), t, g.ID); err != nil && !errors.Is(err, store.ErrNotFound) {
			s.fail(w, r, err)
			return
		}
		s.audit(r.Context(), t, op, "group.deleted", g.ID, map[string]any{"name": g.Name})
		s.flash(w, r, s.Tf(r, "Gruppo %s eliminato.", g.Name), "/groups")
	case "remove":
		members := r.PostForm["member"]
		if len(members) == 0 {
			s.flash(w, r, s.T(r, "Seleziona i membri da togliere."), back)
			return
		}
		if err := s.store.RemoveGroupMembers(r.Context(), t, g.ID, members); err != nil {
			s.fail(w, r, err)
			return
		}
		s.audit(r.Context(), t, op, "group.members_removed", g.ID, map[string]any{"members": members})
		s.flash(w, r, s.Tf(r, "%d membri tolti dal gruppo.", len(members)), back)
	case "add":
		s.addFromForm(w, r, t, g)
	default:
		http.Error(w, s.T(r, "richiesta non valida"), http.StatusBadRequest)
	}
}

// addFromForm adds the selected agents ("agent" values), or the computer
// or user names typed one per line ("names").
func (s *Server) addFromForm(w http.ResponseWriter, r *http.Request, t string, g store.Group) {
	back := "/groups/" + g.ID
	var add, unknown []string
	names := strings.FieldsFunc(r.PostFormValue("names"), func(c rune) bool { return c == '\n' || c == '\r' || c == ',' || c == ';' })
	switch {
	case g.Kind == store.GroupComputer && len(names) > 0:
		all, err := s.tenantAgents(r, t)
		if err != nil {
			s.fail(w, r, err)
			return
		}
		for _, n := range names {
			n = strings.TrimSpace(n)
			if n == "" {
				continue
			}
			found := false
			for _, a := range all {
				if strings.EqualFold(a.Host.Hostname, n) {
					add, found = append(add, a.ID), true
				}
			}
			if !found {
				unknown = append(unknown, n)
			}
		}
	case g.Kind == store.GroupComputer:
		add = validIDs(r.PostForm["agent"])
	default:
		for _, n := range names {
			n = strings.TrimSpace(n)
			if n == "" {
				continue
			}
			if len(n) > maxUserName || strings.ContainsFunc(n, unicode.IsControl) {
				unknown = append(unknown, n)
				continue
			}
			add = append(add, n)
		}
	}
	if len(add)+len(g.Members) > maxGroupMembers {
		s.flash(w, r, s.Tf(r, "Un gruppo ha al massimo %d membri.", maxGroupMembers), back)
		return
	}
	if len(add) > 0 {
		if err := s.addGroupMembers(r, t, g, add); err != nil {
			s.fail(w, r, err)
			return
		}
	}
	if len(unknown) > 0 {
		back += "?" + url.Values{"unknown": {strings.Join(unknown, ", ")}}.Encode()
	}
	s.flash(w, r, s.Tf(r, "%d membri aggiunti al gruppo.", len(add)), back)
}

// handleGroupAgents adds the agents selected in the bulk actions to a group.
func (s *Server) handleGroupAgents(w http.ResponseWriter, r *http.Request) {
	t, ok := tenantOf(r)
	if !ok {
		http.Error(w, s.T(r, "nessun tenant"), http.StatusForbidden)
		return
	}
	g, err := s.findGroup(r, t, r.PostFormValue("group"))
	if errors.Is(err, store.ErrNotFound) || (err == nil && g.Kind != store.GroupComputer) {
		s.flash(w, r, s.T(r, "Scegli un gruppo di computer."), "/groups")
		return
	}
	if err != nil {
		s.fail(w, r, err)
		return
	}
	r.PostForm.Del("names")
	s.addFromForm(w, r, t, g)
}
