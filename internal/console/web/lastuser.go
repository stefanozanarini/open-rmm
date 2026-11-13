package web

import (
	"context"
	"time"

	"github.com/stefanozanarini/tempra-rmm/internal/console/store"
)

// userView is the user shown for a computer: the one logged on, or for a
// few days (Settings.LastUserDays) the last one seen.
type userView struct {
	Name string
	// Last: not seen logged on now (computer offline or nobody logged on
	// at the last inventory); Seen is when it was.
	Last bool
	Seen time.Time
}

// lastUsers loads the last users of a tenant and how long to show them.
func (s *Server) lastUsers(ctx context.Context, t string) (map[string]store.LastUser, time.Duration) {
	ttl := time.Duration(store.DefaultLastUserDays) * 24 * time.Hour
	if set, err := s.store.GetSettings(ctx, t); err == nil {
		ttl = set.LastUserTTL()
	}
	lu, err := s.store.LastUsers(ctx, t)
	if err != nil {
		s.log.Warn("last users", "err", err)
	}
	return lu, ttl
}

// userFor picks the user to show for an agent: the one the inventory found
// logged on, unless a later logon (or, while nobody is logged on, the last
// user seen within ttl) says otherwise. Last marks a user not known to be
// there now: the computer is offline, or nobody was logged on at the last
// inventory.
func (s *Server) userFor(a store.Agent, inv store.InventorySummary, lu store.LastUser, has bool, ttl time.Duration) userView {
	online := s.online(a)
	current := userView{Name: inv.LoggedOnUser, Last: !online, Seen: inv.CollectedAt}
	if !has || s.now().Sub(lu.SeenAt) > ttl || (inv.LoggedOnUser != "" && !lu.SeenAt.After(inv.CollectedAt)) {
		return current
	}
	return userView{Name: lu.User, Last: !online || !lu.SeenAt.After(inv.CollectedAt), Seen: lu.SeenAt}
}
