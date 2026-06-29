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

package gcpkms_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"net"
	"strings"
	"testing"

	kms "cloud.google.com/go/kms/apiv1"
	"cloud.google.com/go/kms/apiv1/kmspb"
	"github.com/deep-rent/nexus/vault/gcpkms"
	"google.golang.org/api/option"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

type mockServer struct {
	kmspb.UnimplementedKeyManagementServiceServer
}

func (s *mockServer) ListCryptoKeyVersions(
	ctx context.Context,
	req *kmspb.ListCryptoKeyVersionsRequest,
) (*kmspb.ListCryptoKeyVersionsResponse, error) {
	versions := []*kmspb.CryptoKeyVersion{
		{
			Name:      req.Parent + "/cryptoKeyVersions/1",
			Algorithm: kmspb.CryptoKeyVersion_RSA_SIGN_PKCS1_2048_SHA256,
		},
	}
	if !strings.HasSuffix(req.Parent, "ck-rsa") {
		versions = append(versions, &kmspb.CryptoKeyVersion{
			Name:      req.Parent + "/cryptoKeyVersions/2",
			Algorithm: kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256,
		}, &kmspb.CryptoKeyVersion{
			Name:      req.Parent + "/cryptoKeyVersions/unsupported",
			Algorithm: kmspb.CryptoKeyVersion_HMAC_SHA256,
		})
	}

	return &kmspb.ListCryptoKeyVersionsResponse{
		CryptoKeyVersions: versions,
	}, nil
}

func (s *mockServer) GetPublicKey(
	ctx context.Context,
	req *kmspb.GetPublicKeyRequest,
) (*kmspb.PublicKey, error) {
	var pemStr string
	if strings.HasSuffix(req.Name, "cryptoKeyVersions/1") {
		pemStr = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnG0D6EYAzGp75rvEFrBM
SdhSzHmuPPmfH+s6x0gcHvePj84WyjZp+0XbOvmqLK9AIw7KM7yf23/bsjRVZaR9
SCQGNqtVxo5JgXlJAq9Tvpwdq+iwBFrORMI1Aonx2WqDJtmT+RraSkDiX0ESUELR
QYVTaGne/0yArGgDMiO1NaQAvm8IIOgY4efxIbruNd5omb0gabuJdr/rc9lY5x6k
qcES2WVMiE4Ot/GDI1KiHSw2eqVgQStmA2TOCfKJHw0/9FFT4GfBMvxsPYT0ePCJ
dGONSwA5mlhSGqYVQDlVfvnLabchYiItXDqe+WxFbFKYzSgM4GwQy8PKojwGKvIt
owIDAQAB
-----END PUBLIC KEY-----`
	} else if strings.HasSuffix(req.Name, "cryptoKeyVersions/2") {
		pk, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		der, _ := x509.MarshalPKIXPublicKey(&pk.PublicKey)
		pemStr = string(pem.EncodeToMemory(&pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: der,
		}))
	} else {
		return nil, errors.New("not found")
	}
	return &kmspb.PublicKey{
		Pem: pemStr,
	}, nil
}

func (s *mockServer) AsymmetricSign(
	ctx context.Context,
	req *kmspb.AsymmetricSignRequest,
) (*kmspb.AsymmetricSignResponse, error) {
	return &kmspb.AsymmetricSignResponse{
		Signature:            []byte("foo"),
		SignatureCrc32C:      wrapperspb.Int64(3485773341),
		VerifiedDigestCrc32C: true,
		Name:                 req.Name,
	}, nil
}

var _ kmspb.KeyManagementServiceServer = (*mockServer)(nil)

func setupTest(t *testing.T) (*kms.KeyManagementClient, func()) {
	t.Helper()
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

	ctx := t.Context()
	conn, err := grpc.NewClient(
		listener.Addr().String(),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatalf("failed to dial: %v", err)
	}

	client, err := kms.NewKeyManagementClient(ctx, option.WithGRPCConn(conn))
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	cleanup := func() {
		client.Close()
		conn.Close()
		srv.Stop()
	}
	return client, cleanup
}

func TestFactory_New(t *testing.T) {
	t.Parallel()

	client, cleanup := setupTest(t)
	defer cleanup()

	f := gcpkms.NewFactory(client, gcpkms.WithContext(t.Context()))

	parent := "projects/test/locations/global/keyRings/kr/cryptoKeys/ck"
	v, err := f.New(parent)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if got, want := v.Keys().Len(), 2; got != want {
		t.Errorf("Keys().Len() = %d; want %d", got, want)
	}
}

func TestSigner_Sign(t *testing.T) {
	t.Parallel()

	client, cleanup := setupTest(t)
	defer cleanup()

	f := gcpkms.NewFactory(client)

	parent := "projects/test/locations/global/keyRings/kr/cryptoKeys/ck-rsa"
	v, err := f.New(parent)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	signer := v.Next()
	msg := []byte("payload")
	sig, err := signer.Sign(t.Context(), msg)
	if err != nil {
		t.Fatalf("unexpected error during sign: %v", err)
	}

	if string(sig) != "foo" {
		t.Errorf("expected %q signature, got %q", "foo", string(sig))
	}
}
