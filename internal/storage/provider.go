package storage

import (
	"context"
	"io"
	"time"
)

type CloudProvider interface {
	Authenticate(ctx context.Context) error

	ListDirectory(ctx context.Context, path string) ([]FileMetadata, error)
	CreateDirectory(ctx context.Context, path string) error
	DeleteNode(ctx context.Context, path string) error

	UploadStream(ctx context.Context, path string, stream io.Reader, size int64) (*FileMetadata, error)
	DownloadStream(ctx context.Context, path string) (io.ReadCloser, error)
}

type FileMetadata struct {
	Path        string
	RemoteID    string
	ParentID    string
	Name        string
	Size        int64
	SHA256      string
	CreatedAt   time.Time
	ModifiedAt  time.Time
	IsDirectory bool
}
