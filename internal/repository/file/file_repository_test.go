package file

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/alisonui/why-blocked/internal/decision"
	"github.com/alisonui/why-blocked/internal/repository"
)

func createTestDecision(id, name, namespace string, ts time.Time) decision.SecurityDecision {
	return decision.SecurityDecision{
		ID:        id,
		Timestamp: ts,
		Version:   "v1alpha1",
		Status:    decision.StatusBlocked,
		Summary:   "Test decision",
		Resource: decision.ResourceRef{
			Kind:      "Deployment",
			Name:      name,
			Namespace: namespace,
		},
	}
}

func TestNew(t *testing.T) {
	dir := t.TempDir()

	repo, err := New(dir)
	if err != nil {
		t.Fatalf("New() error = %v, want nil", err)
	}
	if repo == nil {
		t.Fatal("New() returned nil repository")
	}

	// Verify directory was created
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		t.Errorf("New() did not create directory %s", dir)
	}
}

func TestNew_CreatesNestedDirectory(t *testing.T) {
	baseDir := t.TempDir()
	nestedDir := filepath.Join(baseDir, "nested", "path", "decisions")

	repo, err := New(nestedDir)
	if err != nil {
		t.Fatalf("New() error = %v, want nil", err)
	}
	if repo == nil {
		t.Fatal("New() returned nil repository")
	}

	// Verify nested directory was created
	if _, err := os.Stat(nestedDir); os.IsNotExist(err) {
		t.Errorf("New() did not create nested directory %s", nestedDir)
	}
}

func TestSave(t *testing.T) {
	dir := t.TempDir()
	repo, err := New(dir)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	d := createTestDecision("test-123", "app", "default", time.Date(2026, 2, 5, 16, 0, 0, 0, time.UTC))

	err = repo.Save(d)
	if err != nil {
		t.Fatalf("Save() error = %v, want nil", err)
	}

	// Verify file was created with correct naming pattern
	files, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir() error = %v", err)
	}

	foundDecisionFile := false
	foundLatestFile := false
	for _, f := range files {
		if f.Name() == "latest.json" {
			foundLatestFile = true
		} else if filepath.Ext(f.Name()) == ".json" {
			foundDecisionFile = true
			// Verify filename format: <timestamp>_<id>.json
			// Just check it ends with _test-123.json
			expectedSuffix := "_test-123.json"
			if len(f.Name()) < len(expectedSuffix) || f.Name()[len(f.Name())-len(expectedSuffix):] != expectedSuffix {
				t.Errorf("Save() created file %s, expected it to end with %s", f.Name(), expectedSuffix)
			}
		}
	}

	if !foundDecisionFile {
		t.Error("Save() did not create decision file")
	}
	if !foundLatestFile {
		t.Error("Save() did not create latest.json")
	}
}

func TestSave_InvalidDecision(t *testing.T) {
	dir := t.TempDir()
	repo, err := New(dir)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	// Create invalid decision (missing ID)
	d := createTestDecision("", "app", "default", time.Now())

	err = repo.Save(d)
	if err == nil {
		t.Fatal("Save() error = nil, want error for invalid decision")
	}
	if !errors.Is(err, repository.ErrInvalidData) {
		t.Errorf("Save() error = %v, want %v", err, repository.ErrInvalidData)
	}
}

func TestGetByID(t *testing.T) {
	dir := t.TempDir()
	repo, err := New(dir)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	// Save a decision
	d := createTestDecision("test-456", "myapp", "production", time.Date(2026, 2, 5, 16, 0, 0, 0, time.UTC))
	if err := repo.Save(d); err != nil {
		t.Fatalf("Save() error = %v", err)
	}

	// Retrieve by ID
	retrieved, err := repo.GetByID("test-456")
	if err != nil {
		t.Fatalf("GetByID() error = %v, want nil", err)
	}

	if retrieved.ID != d.ID {
		t.Errorf("GetByID() ID = %v, want %v", retrieved.ID, d.ID)
	}
	if retrieved.Resource.Name != d.Resource.Name {
		t.Errorf("GetByID() Resource.Name = %v, want %v", retrieved.Resource.Name, d.Resource.Name)
	}
	if retrieved.Resource.Namespace != d.Resource.Namespace {
		t.Errorf("GetByID() Resource.Namespace = %v, want %v", retrieved.Resource.Namespace, d.Resource.Namespace)
	}
}

func TestGetByID_NotFound(t *testing.T) {
	dir := t.TempDir()
	repo, err := New(dir)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	_, err = repo.GetByID("nonexistent")
	if err == nil {
		t.Fatal("GetByID() error = nil, want error for nonexistent ID")
	}
	if !errors.Is(err, repository.ErrNotFound) {
		t.Errorf("GetByID() error = %v, want %v", err, repository.ErrNotFound)
	}
}

func TestGetLatest(t *testing.T) {
	dir := t.TempDir()
	repo, err := New(dir)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	// Save multiple decisions for the same resource at different times
	d1 := createTestDecision("dec-1", "myapp", "production", time.Date(2026, 2, 5, 14, 0, 0, 0, time.UTC))
	d2 := createTestDecision("dec-2", "myapp", "production", time.Date(2026, 2, 5, 15, 0, 0, 0, time.UTC))
	d3 := createTestDecision("dec-3", "myapp", "production", time.Date(2026, 2, 5, 16, 0, 0, 0, time.UTC))

	if err := repo.Save(d1); err != nil {
		t.Fatalf("Save(d1) error = %v", err)
	}
	if err := repo.Save(d2); err != nil {
		t.Fatalf("Save(d2) error = %v", err)
	}
	if err := repo.Save(d3); err != nil {
		t.Fatalf("Save(d3) error = %v", err)
	}

	// Get latest should return d3
	latest, err := repo.GetLatest("Deployment", "myapp", "production")
	if err != nil {
		t.Fatalf("GetLatest() error = %v, want nil", err)
	}

	if latest.ID != "dec-3" {
		t.Errorf("GetLatest() ID = %v, want dec-3", latest.ID)
	}
}

func TestGetLatest_DifferentResources(t *testing.T) {
	dir := t.TempDir()
	repo, err := New(dir)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	// Save decisions for different resources
	d1 := createTestDecision("dec-1", "app1", "production", time.Date(2026, 2, 5, 16, 0, 0, 0, time.UTC))
	d2 := createTestDecision("dec-2", "app2", "production", time.Date(2026, 2, 5, 16, 0, 0, 0, time.UTC))
	d3 := createTestDecision("dec-3", "app1", "staging", time.Date(2026, 2, 5, 16, 0, 0, 0, time.UTC))

	if err := repo.Save(d1); err != nil {
		t.Fatalf("Save(d1) error = %v", err)
	}
	if err := repo.Save(d2); err != nil {
		t.Fatalf("Save(d2) error = %v", err)
	}
	if err := repo.Save(d3); err != nil {
		t.Fatalf("Save(d3) error = %v", err)
	}

	// Get latest for app1 in production
	latest, err := repo.GetLatest("Deployment", "app1", "production")
	if err != nil {
		t.Fatalf("GetLatest() error = %v, want nil", err)
	}
	if latest.ID != "dec-1" {
		t.Errorf("GetLatest() ID = %v, want dec-1", latest.ID)
	}

	// Get latest for app2 in production
	latest, err = repo.GetLatest("Deployment", "app2", "production")
	if err != nil {
		t.Fatalf("GetLatest() error = %v, want nil", err)
	}
	if latest.ID != "dec-2" {
		t.Errorf("GetLatest() ID = %v, want dec-2", latest.ID)
	}

	// Get latest for app1 in staging
	latest, err = repo.GetLatest("Deployment", "app1", "staging")
	if err != nil {
		t.Fatalf("GetLatest() error = %v, want nil", err)
	}
	if latest.ID != "dec-3" {
		t.Errorf("GetLatest() ID = %v, want dec-3", latest.ID)
	}
}

func TestGetLatest_NotFound(t *testing.T) {
	dir := t.TempDir()
	repo, err := New(dir)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	_, err = repo.GetLatest("Deployment", "nonexistent", "production")
	if err == nil {
		t.Fatal("GetLatest() error = nil, want error for nonexistent resource")
	}
	if !errors.Is(err, repository.ErrNotFound) {
		t.Errorf("GetLatest() error = %v, want %v", err, repository.ErrNotFound)
	}
}

func TestList(t *testing.T) {
	dir := t.TempDir()
	repo, err := New(dir)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	// Save multiple decisions
	d1 := createTestDecision("dec-1", "app1", "production", time.Date(2026, 2, 5, 14, 0, 0, 0, time.UTC))
	d2 := createTestDecision("dec-2", "app2", "production", time.Date(2026, 2, 5, 15, 0, 0, 0, time.UTC))
	d3 := createTestDecision("dec-3", "app3", "staging", time.Date(2026, 2, 5, 16, 0, 0, 0, time.UTC))

	if err := repo.Save(d1); err != nil {
		t.Fatalf("Save(d1) error = %v", err)
	}
	if err := repo.Save(d2); err != nil {
		t.Fatalf("Save(d2) error = %v", err)
	}
	if err := repo.Save(d3); err != nil {
		t.Fatalf("Save(d3) error = %v", err)
	}

	// List all decisions
	decisions, err := repo.List("", 10)
	if err != nil {
		t.Fatalf("List() error = %v, want nil", err)
	}

	if len(decisions) != 3 {
		t.Errorf("List() returned %d decisions, want 3", len(decisions))
	}

	// Verify they are sorted by timestamp descending (newest first)
	if decisions[0].ID != "dec-3" {
		t.Errorf("List() first decision ID = %v, want dec-3", decisions[0].ID)
	}
	if decisions[2].ID != "dec-1" {
		t.Errorf("List() last decision ID = %v, want dec-1", decisions[2].ID)
	}
}

func TestList_FilterByNamespace(t *testing.T) {
	dir := t.TempDir()
	repo, err := New(dir)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	// Save decisions in different namespaces
	d1 := createTestDecision("dec-1", "app1", "production", time.Date(2026, 2, 5, 14, 0, 0, 0, time.UTC))
	d2 := createTestDecision("dec-2", "app2", "production", time.Date(2026, 2, 5, 15, 0, 0, 0, time.UTC))
	d3 := createTestDecision("dec-3", "app3", "staging", time.Date(2026, 2, 5, 16, 0, 0, 0, time.UTC))

	if err := repo.Save(d1); err != nil {
		t.Fatalf("Save(d1) error = %v", err)
	}
	if err := repo.Save(d2); err != nil {
		t.Fatalf("Save(d2) error = %v", err)
	}
	if err := repo.Save(d3); err != nil {
		t.Fatalf("Save(d3) error = %v", err)
	}

	// List only production namespace
	decisions, err := repo.List("production", 10)
	if err != nil {
		t.Fatalf("List() error = %v, want nil", err)
	}

	if len(decisions) != 2 {
		t.Errorf("List('production') returned %d decisions, want 2", len(decisions))
	}

	for _, d := range decisions {
		if d.Resource.Namespace != "production" {
			t.Errorf("List('production') returned decision with namespace %v", d.Resource.Namespace)
		}
	}
}

func TestList_Limit(t *testing.T) {
	dir := t.TempDir()
	repo, err := New(dir)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	// Save 5 decisions
	for i := 1; i <= 5; i++ {
		d := createTestDecision(
			"dec-"+string(rune('0'+i)),
			"app",
			"default",
			time.Date(2026, 2, 5, 10+i, 0, 0, 0, time.UTC),
		)
		if err := repo.Save(d); err != nil {
			t.Fatalf("Save() error = %v", err)
		}
	}

	// List with limit of 3
	decisions, err := repo.List("", 3)
	if err != nil {
		t.Fatalf("List() error = %v, want nil", err)
	}

	if len(decisions) != 3 {
		t.Errorf("List(limit=3) returned %d decisions, want 3", len(decisions))
	}
}

func TestList_Empty(t *testing.T) {
	dir := t.TempDir()
	repo, err := New(dir)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	decisions, err := repo.List("", 10)
	if err != nil {
		t.Fatalf("List() error = %v, want nil", err)
	}

	if len(decisions) != 0 {
		t.Errorf("List() returned %d decisions, want 0", len(decisions))
	}
}

func TestSave_FilenameWithSeparator(t *testing.T) {
	dir := t.TempDir()
	repo, err := New(dir)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	// Create decision with ID containing path separator
	d := createTestDecision("test/with/slash", "app", "default", time.Date(2026, 2, 5, 16, 0, 0, 0, time.UTC))

	err = repo.Save(d)
	if err != nil {
		t.Fatalf("Save() error = %v, want nil", err)
	}

	// Verify file was created with sanitized filename
	files, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir() error = %v", err)
	}

	foundSanitized := false
	for _, f := range files {
		if f.Name() != "latest.json" && filepath.Ext(f.Name()) == ".json" {
			// Should contain dashes instead of slashes in the ID part
			// Format: <timestamp>_test-with-slash.json
			if filepath.Ext(f.Name()) == ".json" &&
				(f.Name()[len(f.Name())-len("_test-with-slash.json"):] == "_test-with-slash.json") {
				foundSanitized = true
			}
		}
	}

	if !foundSanitized {
		t.Error("Save() did not sanitize filename with path separators")
	}

	// Verify we can retrieve it
	retrieved, err := repo.GetByID("test/with/slash")
	if err != nil {
		t.Fatalf("GetByID() error = %v, want nil", err)
	}
	if retrieved.ID != "test/with/slash" {
		t.Errorf("GetByID() ID = %v, want test/with/slash", retrieved.ID)
	}
}
