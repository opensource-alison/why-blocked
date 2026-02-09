package file

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/alisonui/why-blocked/internal/decision"
	"github.com/alisonui/why-blocked/internal/repository"
)

type FileDecisionRepository struct {
	dir string
}

func New(dir string) (*FileDecisionRepository, error) {
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create repository directory %s: %w", dir, err)
	}
	return &FileDecisionRepository{dir: dir}, nil
}

func (r *FileDecisionRepository) Save(d decision.SecurityDecision) error {
	if err := d.Validate(); err != nil {
		return fmt.Errorf("%w: %v", repository.ErrInvalidData, err)
	}

	data, err := json.MarshalIndent(d, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal decision: %w", err)
	}

	// Filename format: <unixTs>_<safeDecisionID>.json
	safeID := strings.ReplaceAll(d.ID, string(filepath.Separator), "-")
	filename := fmt.Sprintf("%d_%s.json", d.Timestamp.Unix(), safeID)
	path := filepath.Join(r.dir, filename)

	if err := WriteAtomic(path, data, 0644); err != nil {
		return fmt.Errorf("failed to save decision to %s: %w", path, err)
	}

	// Update latest.json
	latestPath := filepath.Join(r.dir, "latest.json")
	if err := WriteAtomic(latestPath, data, 0644); err != nil {
		return fmt.Errorf("failed to update latest.json: %w", err)
	}

	return nil
}

func (r *FileDecisionRepository) GetByID(id string) (decision.SecurityDecision, error) {
	files, err := r.listDecisionFiles()
	if err != nil {
		return decision.SecurityDecision{}, err
	}

	for _, f := range files {
		if strings.HasSuffix(f.Name(), "_"+id+".json") {
			return r.readFile(f.Name())
		}
	}

	for _, f := range files {
		d, err := r.readFile(f.Name())
		if err == nil && d.ID == id {
			return d, nil
		}
	}

	return decision.SecurityDecision{}, fmt.Errorf("decision %s: %w", id, repository.ErrNotFound)
}

func (r *FileDecisionRepository) GetLatest(kind, name, namespace string) (decision.SecurityDecision, error) {
	files, err := r.listDecisionFiles()
	if err != nil {
		return decision.SecurityDecision{}, err
	}

	sort.Slice(files, func(i, j int) bool {
		return files[i].Name() > files[j].Name()
	})

	for _, f := range files {
		d, err := r.readFile(f.Name())
		if err != nil {
			continue
		}

		if d.Resource.Kind == kind && d.Resource.Name == name && d.Resource.Namespace == namespace {
			return d, nil
		}
	}

	return decision.SecurityDecision{}, fmt.Errorf("latest decision for %s/%s in %s: %w", kind, name, namespace, repository.ErrNotFound)
}

func (r *FileDecisionRepository) List(namespace string, limit int) ([]decision.SecurityDecision, error) {
	files, err := r.listDecisionFiles()
	if err != nil {
		return nil, err
	}

	sort.Slice(files, func(i, j int) bool {
		return files[i].Name() > files[j].Name()
	})

	var result []decision.SecurityDecision
	for _, f := range files {
		d, err := r.readFile(f.Name())
		if err != nil {
			continue
		}

		if namespace != "" && d.Resource.Namespace != namespace {
			continue
		}

		result = append(result, d)
		if limit > 0 && len(result) >= limit {
			break
		}
	}

	return result, nil
}

func (r *FileDecisionRepository) listDecisionFiles() ([]os.DirEntry, error) {
	files, err := os.ReadDir(r.dir)
	if err != nil {
		return nil, fmt.Errorf("failed to read directory: %w", err)
	}

	var result []os.DirEntry
	for _, f := range files {
		if !f.IsDir() && f.Name() != "latest.json" && strings.HasSuffix(f.Name(), ".json") {
			result = append(result, f)
		}
	}
	return result, nil
}

func (r *FileDecisionRepository) readFile(name string) (decision.SecurityDecision, error) {
	path := filepath.Join(r.dir, name)
	data, err := os.ReadFile(path)
	if err != nil {
		return decision.SecurityDecision{}, fmt.Errorf("failed to read file %s: %w", path, err)
	}

	var d decision.SecurityDecision
	if err := json.Unmarshal(data, &d); err != nil {
		return decision.SecurityDecision{}, fmt.Errorf("%w: failed to unmarshal %s: %v", repository.ErrInvalidData, path, err)
	}

	if err := d.Validate(); err != nil {
		return decision.SecurityDecision{}, fmt.Errorf("%w: invalid decision in %s: %v", repository.ErrInvalidData, path, err)
	}

	return d, nil
}

// BaseDir returns the base directory where decisions are stored.
func (r *FileDecisionRepository) BaseDir() string {
	return r.dir
}
