// Copyright (c) 2025-present deep.rent GmbH (https://deep.rent)
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package google_test

import (
	"context"
	"crypto"
	"net"
	"strings"
	"testing"

	kms "cloud.google.com/go/kms/apiv1"
	"cloud.google.com/go/kms/apiv1/kmspb"
	"google.golang.org/api/option"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"github.com/deep-rent/nexus/signer/google"
)

type mockServer struct {
	kmspb.UnimplementedKeyManagementServiceServer
}

func (s *mockServer) GetPublicKey(
	ctx context.Context,
	req *kmspb.GetPublicKeyRequest,
) (*kmspb.PublicKey, error) {
	const pem = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnG0D6EYAzGp75rvEFrBM
SdhSzHmuPPmfH+s6x0gcHvePj84WyjZp+0XbOvmqLK9AIw7KM7yf23/bsjRVZaR9
SCQGNqtVxo5JgXlJAq9Tvpwdq+iwBFrORMI1Aonx2WqDJtmT+RraSkDiX0ESUELR
QYVTaGne/0yArGgDMiO1NaQAvm8IIOgY4efxIbruNd5omb0gabuJdr/rc9lY5x6k
qcES2WVMiE4Ot/GDI1KiHSw2eqVgQStmA2TOCfKJHw0/9FFT4GfBMvxsPYT0ePCJ
dGONSwA5mlhSGqYVQDlVfvnLabchYiItXDqe+WxFbFKYzSgM4GwQy8PKojwGKvIt
owIDAQAB
-----END PUBLIC KEY-----`
	return &kmspb.PublicKey{
		Pem: pem,
	}, nil
}

func (s *mockServer) AsymmetricSign(
	ctx context.Context,
	req *kmspb.AsymmetricSignRequest,
) (*kmspb.AsymmetricSignResponse, error) {
	return &kmspb.AsymmetricSignResponse{
		Signature:            []byte("foo"),
		SignatureCrc32C:      wrapperspb.Int64(2339757342),
		VerifiedDigestCrc32C: true,
		Name:                 req.Name,
	}, nil
}

var _ kmspb.KeyManagementServiceServer = (*mockServer)(nil)

func TestSigner(t *testing.T) {
	t.Parallel()

	listener, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}

	srv := grpc.NewServer()
	kmspb.RegisterKeyManagementServiceServer(srv, &mockServer{})
	go func() {
		if err := srv.Serve(listener); err != nil {
			t.Logf("server stopped: %v", err)
		}
	}()
	defer srv.Stop()

	ctx := t.Context()
	conn, err := grpc.NewClient(
		listener.Addr().String(),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatalf("failed to dial: %v", err)
	}
	defer func() {
		if err := conn.Close(); err != nil {
			t.Logf("failed to close connection: %v", err)
		}
	}()

	client, err := kms.NewKeyManagementClient(ctx, option.WithGRPCConn(conn))
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}
	defer func() {
		if err := client.Close(); err != nil {
			t.Logf("failed to close client: %v", err)
		}
	}()

	name := strings.Join([]string{
		"projects",
		"test",
		"locations",
		"global",
		"keyRings",
		"kr",
		"cryptoKeys",
		"ck",
		"cryptoKeyVersions",
		"1",
	}, "/")
	signer, err := google.New(ctx, client, name)
	if err != nil {
		t.Fatalf("failed to create signer: %v", err)
	}

	if signer.Public() == nil {
		t.Error("expected non-nil public key")
	}

	digest := make([]byte, 32)
	sig, err := signer.Sign(ctx, nil, digest, crypto.SHA256)
	if err != nil {
		t.Fatalf("unexpected error during sign: %v", err)
	}

	if exp, act := "foo", string(sig); exp != act {
		t.Errorf("expected %q signature, got %q", exp, act)
	}
}
