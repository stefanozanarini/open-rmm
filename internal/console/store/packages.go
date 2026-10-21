package store

import (
	"context"
	"errors"
	"sort"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// ErrPackageExists is returned when the tenant already has the package.
var ErrPackageExists = errors.New("package already in the library")

// Package kinds: how the software module installs it.
const (
	KindMSI      = "msi"
	KindExe      = "exe"      // silent arguments required
	KindInno     = "inno"     // Inno Setup
	KindNullsoft = "nullsoft" // NSIS
	KindBurn     = "burn"     // WiX bundle
)

// ValidKind reports whether k is a supported package kind.
func ValidKind(k string) bool {
	switch k {
	case KindMSI, KindExe, KindInno, KindNullsoft, KindBurn:
		return true
	}
	return false
}

// Package is an entry of the tenant's package library.
type Package struct {
	TenantID      string
	SHA256        string // hex
	Name          string
	Version       string
	Publisher     string
	FileName      string
	Size          int64
	Kind          string
	SilentArgs    string
	ProductCode   string
	AllowUnsigned bool
	Source        string // upload | winget
	WingetID      string
	SourceURL     string
	CreatedBy     string
	CreatedAt     time.Time
}

// PackageStore keeps the package library metadata.
type PackageStore interface {
	PutPackage(ctx context.Context, p Package) error
	GetPackage(ctx context.Context, tenantID, sha256 string) (Package, error)
	ListPackages(ctx context.Context, tenantID string) ([]Package, error)
	// SetPackageUnsigned allows or forbids installing a package whose file
	// has no valid Authenticode signature.
	SetPackageUnsigned(ctx context.Context, tenantID, sha256 string, allow bool) error
}

func (m *Memory) SetPackageUnsigned(_ context.Context, tenantID, sha string, allow bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	p, ok := m.packages[tenantID+"/"+sha]
	if !ok {
		return ErrNotFound
	}
	p.AllowUnsigned = allow
	m.packages[tenantID+"/"+sha] = p
	return nil
}

func (p *Postgres) SetPackageUnsigned(ctx context.Context, tenantID, sha string, allow bool) error {
	return p.inTenant(ctx, tenantID, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `UPDATE packages SET allow_unsigned = $1 WHERE sha256 = $2`, allow, sha)
		if err == nil && tag.RowsAffected() == 0 {
			return ErrNotFound
		}
		return err
	})
}

// ---- memory ----

func (m *Memory) PutPackage(_ context.Context, p Package) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.packages == nil {
		m.packages = map[string]Package{}
	}
	k := p.TenantID + "/" + p.SHA256
	if _, ok := m.packages[k]; ok {
		return ErrPackageExists
	}
	if p.CreatedAt.IsZero() {
		p.CreatedAt = time.Now()
	}
	m.packages[k] = p
	return nil
}

func (m *Memory) GetPackage(_ context.Context, tenantID, sha string) (Package, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	p, ok := m.packages[tenantID+"/"+sha]
	if !ok {
		return Package{}, ErrNotFound
	}
	return p, nil
}

func (m *Memory) ListPackages(_ context.Context, tenantID string) ([]Package, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []Package
	for _, p := range m.packages {
		if p.TenantID == tenantID {
			out = append(out, p)
		}
	}
	sortPackages(out)
	return out, nil
}

func sortPackages(out []Package) {
	sort.Slice(out, func(i, j int) bool {
		if out[i].Name != out[j].Name {
			return out[i].Name < out[j].Name
		}
		return out[i].CreatedAt.After(out[j].CreatedAt)
	})
}

// ---- postgres ----

const packageColumns = `tenant_id::text, sha256, name, version, publisher, file_name, size, kind, silent_args, product_code,
	allow_unsigned, source, winget_id, source_url, created_by, created_at`

func scanPackage(row pgx.Row) (Package, error) {
	var p Package
	err := row.Scan(&p.TenantID, &p.SHA256, &p.Name, &p.Version, &p.Publisher, &p.FileName, &p.Size, &p.Kind, &p.SilentArgs,
		&p.ProductCode, &p.AllowUnsigned, &p.Source, &p.WingetID, &p.SourceURL, &p.CreatedBy, &p.CreatedAt)
	return p, err
}

func (p *Postgres) PutPackage(ctx context.Context, pk Package) error {
	err := p.inTenant(ctx, pk.TenantID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO packages (tenant_id, sha256, name, version, publisher, file_name, size, kind,
			silent_args, product_code, allow_unsigned, source, winget_id, source_url, created_by)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)`,
			pk.TenantID, pk.SHA256, pk.Name, pk.Version, pk.Publisher, pk.FileName, pk.Size, pk.Kind, pk.SilentArgs,
			pk.ProductCode, pk.AllowUnsigned, pk.Source, pk.WingetID, pk.SourceURL, pk.CreatedBy)
		return err
	})
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23505" {
		return ErrPackageExists
	}
	return err
}

func (p *Postgres) GetPackage(ctx context.Context, tenantID, sha string) (Package, error) {
	var pk Package
	err := p.inTenant(ctx, tenantID, func(tx pgx.Tx) error {
		var err error
		pk, err = scanPackage(tx.QueryRow(ctx, `SELECT `+packageColumns+` FROM packages WHERE sha256 = $1`, sha))
		return err
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return Package{}, ErrNotFound
	}
	return pk, err
}

func (p *Postgres) ListPackages(ctx context.Context, tenantID string) ([]Package, error) {
	var out []Package
	err := p.inTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT `+packageColumns+` FROM packages`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			pk, err := scanPackage(rows)
			if err != nil {
				return err
			}
			out = append(out, pk)
		}
		return rows.Err()
	})
	sortPackages(out)
	return out, err
}

// CatalogApp is an application followed in the winget catalog.
type CatalogApp struct {
	TenantID       string
	WingetID       string
	Name           string
	Publisher      string
	Version        string
	DisplayVersion string
	MatchName      string
	ProductCodes   []string
	Release        []byte // JSON of the chosen installer (wingetcat.Release)
	CheckedAt      time.Time
	AddedBy        string
}

// CatalogStore keeps the followed applications.
type CatalogStore interface {
	PutCatalogApp(ctx context.Context, a CatalogApp) error // insert or replace
	ListCatalogApps(ctx context.Context, tenantID string) ([]CatalogApp, error)
	GetCatalogApp(ctx context.Context, tenantID, wingetID string) (CatalogApp, error)
	DeleteCatalogApp(ctx context.Context, tenantID, wingetID string) error
}

func (m *Memory) PutCatalogApp(_ context.Context, a CatalogApp) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.catalog == nil {
		m.catalog = map[string]CatalogApp{}
	}
	m.catalog[a.TenantID+"/"+a.WingetID] = a
	return nil
}

func (m *Memory) ListCatalogApps(_ context.Context, tenantID string) ([]CatalogApp, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []CatalogApp
	for _, a := range m.catalog {
		if a.TenantID == tenantID {
			out = append(out, a)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func (m *Memory) GetCatalogApp(_ context.Context, tenantID, wingetID string) (CatalogApp, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	a, ok := m.catalog[tenantID+"/"+wingetID]
	if !ok {
		return CatalogApp{}, ErrNotFound
	}
	return a, nil
}

func (m *Memory) DeleteCatalogApp(_ context.Context, tenantID, wingetID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.catalog[tenantID+"/"+wingetID]; !ok {
		return ErrNotFound
	}
	delete(m.catalog, tenantID+"/"+wingetID)
	return nil
}

const catalogColumns = `tenant_id::text, winget_id, name, publisher, version, display_version, match_name, product_codes,
	release::text, checked_at, added_by`

func scanCatalog(row pgx.Row) (CatalogApp, error) {
	var a CatalogApp
	var rel string
	err := row.Scan(&a.TenantID, &a.WingetID, &a.Name, &a.Publisher, &a.Version, &a.DisplayVersion, &a.MatchName,
		&a.ProductCodes, &rel, &a.CheckedAt, &a.AddedBy)
	a.Release = []byte(rel)
	return a, err
}

func (p *Postgres) PutCatalogApp(ctx context.Context, a CatalogApp) error {
	return p.inTenant(ctx, a.TenantID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO catalog_apps (tenant_id, winget_id, name, publisher, version, display_version,
			match_name, product_codes, release, checked_at, added_by) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9::jsonb,$10,$11)
			ON CONFLICT (tenant_id, winget_id) DO UPDATE SET name = EXCLUDED.name, publisher = EXCLUDED.publisher,
			version = EXCLUDED.version, display_version = EXCLUDED.display_version, match_name = EXCLUDED.match_name,
			product_codes = EXCLUDED.product_codes, release = EXCLUDED.release, checked_at = EXCLUDED.checked_at`,
			a.TenantID, a.WingetID, a.Name, a.Publisher, a.Version, a.DisplayVersion, a.MatchName, nonNil(a.ProductCodes),
			string(a.Release), a.CheckedAt, a.AddedBy)
		return err
	})
}

func (p *Postgres) ListCatalogApps(ctx context.Context, tenantID string) ([]CatalogApp, error) {
	var out []CatalogApp
	err := p.inTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT `+catalogColumns+` FROM catalog_apps ORDER BY name`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			a, err := scanCatalog(rows)
			if err != nil {
				return err
			}
			out = append(out, a)
		}
		return rows.Err()
	})
	return out, err
}

func (p *Postgres) GetCatalogApp(ctx context.Context, tenantID, wingetID string) (CatalogApp, error) {
	var a CatalogApp
	err := p.inTenant(ctx, tenantID, func(tx pgx.Tx) error {
		var err error
		a, err = scanCatalog(tx.QueryRow(ctx, `SELECT `+catalogColumns+` FROM catalog_apps WHERE winget_id = $1`, wingetID))
		return err
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return CatalogApp{}, ErrNotFound
	}
	return a, err
}

func (p *Postgres) DeleteCatalogApp(ctx context.Context, tenantID, wingetID string) error {
	return p.inTenant(ctx, tenantID, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `DELETE FROM catalog_apps WHERE winget_id = $1`, wingetID)
		if err == nil && tag.RowsAffected() == 0 {
			return ErrNotFound
		}
		return err
	})
}
