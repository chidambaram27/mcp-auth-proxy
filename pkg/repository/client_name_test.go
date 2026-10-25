package repository

import (
	"context"
	"path/filepath"
	"testing"
)

func TestClientNameStorage(t *testing.T) {
	newRepos := map[string]func(t *testing.T) Repository{
		"kvs": func(t *testing.T) Repository {
			repo, err := NewKVSRepository(filepath.Join(t.TempDir(), "db"), "test")
			if err != nil {
				t.Fatalf("failed to create kvs repository: %v", err)
			}
			return repo
		},
		"sql": func(t *testing.T) Repository {
			repo, err := NewSQLRepository("sqlite", "file:"+filepath.Join(t.TempDir(), "db.sqlite"))
			if err != nil {
				t.Fatalf("failed to create sql repository: %v", err)
			}
			return repo
		},
	}

	for name, newRepo := range newRepos {
		t.Run(name, func(t *testing.T) {
			repo := newRepo(t)
			defer repo.Close()
			ctx := context.Background()

			got, err := repo.GetClientName(ctx, "missing")
			if err != nil || got != "" {
				t.Fatalf("GetClientName(missing) = %q, %v; want \"\", nil", got, err)
			}

			if err := repo.SetClientName(ctx, "client-1", "Claude"); err != nil {
				t.Fatalf("SetClientName failed: %v", err)
			}
			if err := repo.SetClientName(ctx, "client-1", "Claude Code"); err != nil {
				t.Fatalf("SetClientName (overwrite) failed: %v", err)
			}
			got, err = repo.GetClientName(ctx, "client-1")
			if err != nil || got != "Claude Code" {
				t.Fatalf("GetClientName = %q, %v; want \"Claude Code\", nil", got, err)
			}
		})
	}
}
