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
	"testing"

	kms "cloud.google.com/go/kms/apiv1"
	"cloud.google.com/go/kms/apiv1/kmspb"
	"github.com/deep-rent/nexus/signer/google"
	"google.golang.org/api/option"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

type mockKMSServer struct {
	kmspb.UnimplementedKeyManagementServiceServer
}

func (s *mockKMSServer) GetPublicKey(ctx context.Context, req *kmspb.GetPublicKeyRequest) (*kmspb.PublicKey, error) {
	// A valid PEM block for a dummy public key (RSA 2048)
	const dummyPEM = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnG0D6EYAzGp75rvEFrBM
SdhSzHmuPPmfH+s6x0gcHvePj84WyjZp+0XbOvmqLK9AIw7KM7yf23/bsjRVZaR9
SCQGNqtVxo5JgXlJAq9Tvpwdq+iwBFrORMI1Aonx2WqDJtmT+RraSkDiX0ESUELR
QYVTaGne/0yArGgDMiO1NaQAvm8IIOgY4efxIbruNd5omb0gabuJdr/rc9lY5x6k
qcES2WVMiE4Ot/GDI1KiHSw2eqVgQStmA2TOCfKJHw0/9FFT4GfBMvxsPYT0ePCJ
dGONSwA5mlhSGqYVQDlVfvnLabchYiItXDqe+WxFbFKYzSgM4GwQy8PKojwGKvIt
owIDAQAB
-----END PUBLIC KEY-----`
	return &kmspb.PublicKey{
		Pem: dummyPEM,
	}, nil
}

func (s *mockKMSServer) AsymmetricSign(ctx context.Context, req *kmspb.AsymmetricSignRequest) (*kmspb.AsymmetricSignResponse, error) {
	return &kmspb.AsymmetricSignResponse{
		Signature:            []byte("mock-signature"),
		VerifiedDigestCrc32C: true,
		Name:                 req.Name,
	}, nil
}

func TestSigner(t *testing.T) {
	lis, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}

	grpcServer := grpc.NewServer()
	kmspb.RegisterKeyManagementServiceServer(grpcServer, &mockKMSServer{})
	go grpcServer.Serve(lis)
	defer grpcServer.Stop()

	ctx := context.Background()
	conn, err := grpc.NewClient(lis.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("failed to dial: %v", err)
	}
	defer conn.Close()

	client, err := kms.NewKeyManagementClient(ctx, option.WithGRPCConn(conn))
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}
	defer client.Close()

	keyName := "projects/test/locations/global/keyRings/kr/cryptoKeys/ck/cryptoKeyVersions/1"
	signer, err := google.New(ctx, client, keyName)
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

	if string(sig) != "mock-signature" {
		t.Errorf("expected mock signature, got %s", sig)
	}
}
