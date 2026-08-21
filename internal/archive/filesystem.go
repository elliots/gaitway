package archive

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

type Object struct {
	Ref       string    `json:"ref"`
	SHA256    string    `json:"sha256"`
	Size      int64     `json:"size"`
	Kind      string    `json:"kind"`
	CreatedAt time.Time `json:"created_at"`
}

type Store interface {
	Put(context.Context, string, []byte) (Object, error)
	Read(context.Context, string) ([]byte, error)
}

type Filesystem struct{ root string }

func NewFilesystem(root string) (*Filesystem, error) {
	if root == "" {
		return nil, fmt.Errorf("archive root is required")
	}
	if err := os.MkdirAll(root, 0o700); err != nil {
		return nil, fmt.Errorf("create archive root: %w", err)
	}
	return &Filesystem{root: root}, nil
}

func (f *Filesystem) Put(ctx context.Context, kind string, body []byte) (Object, error) {
	if err := ctx.Err(); err != nil {
		return Object{}, err
	}
	idBytes := make([]byte, 16)
	if _, err := rand.Read(idBytes); err != nil {
		return Object{}, fmt.Errorf("generate object id: %w", err)
	}
	ref := hex.EncodeToString(idBytes)
	digest := sha256.Sum256(body)
	created := time.Now().UTC()
	directory := filepath.Join(f.root, created.Format("2006"), created.Format("01"), created.Format("02"))
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return Object{}, fmt.Errorf("create archive directory: %w", err)
	}
	temporary, err := os.CreateTemp(directory, ".gaitway-*")
	if err != nil {
		return Object{}, fmt.Errorf("create archive temporary file: %w", err)
	}
	temporaryName := temporary.Name()
	defer os.Remove(temporaryName)
	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return Object{}, err
	}
	if _, err := temporary.Write(body); err != nil {
		_ = temporary.Close()
		return Object{}, fmt.Errorf("write archive object: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return Object{}, fmt.Errorf("sync archive object: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return Object{}, fmt.Errorf("close archive object: %w", err)
	}
	name := filepath.Join(directory, ref+".bin")
	if err := os.Rename(temporaryName, name); err != nil {
		return Object{}, fmt.Errorf("publish archive object: %w", err)
	}
	directoryHandle, err := os.Open(directory)
	if err != nil {
		return Object{}, fmt.Errorf("open archive directory: %w", err)
	}
	err = directoryHandle.Sync()
	_ = directoryHandle.Close()
	if err != nil {
		return Object{}, fmt.Errorf("sync archive directory: %w", err)
	}
	return Object{Ref: ref, SHA256: hex.EncodeToString(digest[:]), Size: int64(len(body)), Kind: kind, CreatedAt: created}, nil
}

func (f *Filesystem) Read(ctx context.Context, ref string) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !validRef(ref) {
		return nil, fmt.Errorf("invalid object reference")
	}
	var match string
	err := filepath.WalkDir(f.root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.Type().IsRegular() && entry.Name() == ref+".bin" {
			match = path
			return filepath.SkipAll
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if match == "" {
		return nil, os.ErrNotExist
	}
	return os.ReadFile(match)
}
