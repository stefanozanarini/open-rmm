package gateway

import (
	"context"
	"strings"
	"time"

	"github.com/stefanozanarini/tempra-rmm/internal/console/store"
)

// The last user of each agent: from the inventory when it reports a logged-on
// user, and from interactive logons, which come more often. The console
// shows it for a few days while nobody is logged on or the computer is off.

// interactiveLogon tells whether a logon puts a person in front of the
// computer: console (2), unlock (7), remote interactive (10), cached (11),
// or an RDP session.
func interactiveLogon(e store.LogonEvent) bool {
	switch e.Kind {
	case "rdp_session_logon", "rdp_reconnect":
		return true
	case "logon":
		switch e.LogonType {
		case 2, 7, 10, 11:
			return true
		}
	}
	return false
}

// personUser leaves out system and virtual accounts (Window Manager, font
// driver host, computer accounts).
func personUser(user string) bool {
	u := strings.ToUpper(user)
	if i := strings.LastIndexByte(u, '\\'); i >= 0 {
		u = u[i+1:]
	}
	switch {
	case u == "" || u == "-" || strings.HasSuffix(u, "$"), strings.HasPrefix(u, "DWM-"), strings.HasPrefix(u, "UMFD-"),
		u == "SYSTEM", u == "LOCAL SERVICE", u == "NETWORK SERVICE", u == "ANONYMOUS LOGON":
		return false
	}
	return true
}

// noteLastUser records the last user seen; the agent's clock is not trusted
// to be ahead of the console's.
func (s *Server) noteLastUser(ctx context.Context, a store.Agent, user string, at time.Time, source string) {
	if !personUser(user) {
		return
	}
	if now := s.now(); at.After(now) {
		at = now
	}
	if err := s.store.SetLastUser(ctx, a.TenantID, a.ID, store.LastUser{User: user, SeenAt: at, Source: source}); err != nil {
		s.log.Warn("store last user", "agent", a.ID, "err", err)
	}
}

// noteLogonUser records the latest interactive logon of a batch.
func (s *Server) noteLogonUser(ctx context.Context, a store.Agent, events []store.LogonEvent) {
	var last *store.LogonEvent
	for i := range events {
		e := &events[i]
		if interactiveLogon(*e) && personUser(e.User) && (last == nil || e.At.After(last.At)) {
			last = e
		}
	}
	if last != nil {
		s.noteLastUser(ctx, a, userOf(*last), last.At, store.LastUserLogon)
	}
}
