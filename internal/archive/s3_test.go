package archive

import (
	"context"
	"os"
	"testing"
)

func TestS3Integration(t *testing.T) {
	endpoint := os.Getenv("GAITWAY_TEST_S3_ENDPOINT")
	if endpoint == "" {
		t.Skip("set GAITWAY_TEST_S3_ENDPOINT to run the S3-compatible archive test")
	}
	store, err := NewS3(context.Background(), S3Config{
		Endpoint: endpoint, Bucket: "gaitway-test", AccessKey: "gaitway-local", SecretKey: "gaitway-local-secret",
		AllowHTTP: true, CreateBucket: true, Prefix: "integration",
	})
	if err != nil {
		t.Fatal(err)
	}
	written, err := store.Put(context.Background(), "request", []byte("s3 archive payload"))
	if err != nil {
		t.Fatal(err)
	}
	read, err := store.Read(context.Background(), written.Ref)
	if err != nil {
		t.Fatal(err)
	}
	if string(read) != "s3 archive payload" {
		t.Fatalf("unexpected archive content %q", read)
	}
}
