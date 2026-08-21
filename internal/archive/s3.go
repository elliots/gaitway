package archive

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/url"
	"path"
	"strings"
	"time"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
)

type S3Config struct {
	Endpoint     string
	Region       string
	Bucket       string
	Prefix       string
	AccessKey    string
	SecretKey    string
	SessionToken string
	AllowHTTP    bool
	CreateBucket bool
}

type S3 struct {
	client *minio.Client
	bucket string
	prefix string
}

func NewS3(ctx context.Context, config S3Config) (*S3, error) {
	endpoint, err := url.Parse(config.Endpoint)
	if err != nil || endpoint.Host == "" || endpoint.User != nil || endpoint.RawQuery != "" || endpoint.Fragment != "" || (endpoint.Scheme != "https" && endpoint.Scheme != "http") {
		return nil, fmt.Errorf("S3 endpoint must be an absolute HTTP(S) origin")
	}
	if endpoint.Scheme == "http" && !config.AllowHTTP {
		return nil, fmt.Errorf("S3 endpoint requires HTTPS unless GAITWAY_S3_ALLOW_HTTP is enabled")
	}
	if endpoint.Path != "" && endpoint.Path != "/" {
		return nil, fmt.Errorf("S3 endpoint must not contain a path")
	}
	if config.Bucket == "" || config.AccessKey == "" || config.SecretKey == "" {
		return nil, fmt.Errorf("S3 bucket, access key, and secret key are required")
	}
	client, err := minio.New(endpoint.Host, &minio.Options{
		Creds:        credentials.NewStaticV4(config.AccessKey, config.SecretKey, config.SessionToken),
		Secure:       endpoint.Scheme == "https",
		Region:       config.Region,
		BucketLookup: minio.BucketLookupPath,
		MaxRetries:   1,
	})
	if err != nil {
		return nil, fmt.Errorf("create S3 client: %w", err)
	}
	client.SetAppInfo("gaitway", "dev")
	exists, err := client.BucketExists(ctx, config.Bucket)
	if err != nil {
		return nil, fmt.Errorf("check S3 bucket: %w", err)
	}
	if !exists {
		if !config.CreateBucket {
			return nil, fmt.Errorf("S3 bucket %q does not exist", config.Bucket)
		}
		if err := client.MakeBucket(ctx, config.Bucket, minio.MakeBucketOptions{Region: config.Region}); err != nil {
			return nil, fmt.Errorf("create S3 bucket: %w", err)
		}
	}
	return &S3{client: client, bucket: config.Bucket, prefix: strings.Trim(config.Prefix, "/")}, nil
}

func (s *S3) Put(ctx context.Context, kind string, body []byte) (Object, error) {
	refBytes := make([]byte, 16)
	if _, err := rand.Read(refBytes); err != nil {
		return Object{}, fmt.Errorf("generate object id: %w", err)
	}
	ref := hex.EncodeToString(refBytes)
	digest := sha256.Sum256(body)
	digestText := hex.EncodeToString(digest[:])
	created := time.Now().UTC()
	_, err := s.client.PutObject(ctx, s.bucket, s.key(ref), bytes.NewReader(body), int64(len(body)), minio.PutObjectOptions{
		ContentType: "application/octet-stream",
		UserMetadata: map[string]string{
			"gaitway-sha256":  digestText,
			"gaitway-kind":    kind,
			"gaitway-created": created.Format(time.RFC3339Nano),
		},
	})
	if err != nil {
		return Object{}, fmt.Errorf("put S3 archive object: %w", err)
	}
	return Object{Ref: ref, SHA256: digestText, Size: int64(len(body)), Kind: kind, CreatedAt: created}, nil
}

func (s *S3) Read(ctx context.Context, ref string) ([]byte, error) {
	if !validRef(ref) {
		return nil, fmt.Errorf("invalid object reference")
	}
	object, err := s.client.GetObject(ctx, s.bucket, s.key(ref), minio.GetObjectOptions{})
	if err != nil {
		return nil, err
	}
	defer object.Close()
	info, err := object.Stat()
	if err != nil {
		return nil, err
	}
	body, err := io.ReadAll(object)
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(body)
	want := info.Metadata.Get("X-Amz-Meta-Gaitway-Sha256")
	if want != "" && !strings.EqualFold(want, hex.EncodeToString(digest[:])) {
		return nil, fmt.Errorf("S3 archive checksum mismatch")
	}
	return body, nil
}

func (s *S3) key(ref string) string {
	if s.prefix == "" {
		return ref + ".bin"
	}
	return path.Join(s.prefix, ref+".bin")
}

func validRef(ref string) bool {
	if len(ref) != 32 {
		return false
	}
	for _, char := range ref {
		if !((char >= '0' && char <= '9') || (char >= 'a' && char <= 'f')) {
			return false
		}
	}
	return true
}

var _ Store = (*S3)(nil)
