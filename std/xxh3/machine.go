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

package xxh3

import (
	"encoding/binary"
	"math/bits"
	"unsafe"
)

const (
	prime32_1 uint32 = 0x9E3779B1
	prime32_2 uint32 = 0x85EBCA77
	prime32_3 uint32 = 0xC2B2AE3D

	prime64_1 uint64 = 0x9E3779B185EBCA87
	prime64_2 uint64 = 0xC2B2AE3D27D4EB4F
	prime64_3 uint64 = 0x165667B19E3779F9
	prime64_4 uint64 = 0x85EBCA77C2B2AE63
	prime64_5 uint64 = 0x27D4EB2F165667C5

	secMinSize = 136
	secDefSize = 192
	stripeLen  = 64
	blockLen   = 1024
	midSizeMax = 240
	secStep    = 8
)

// defaultSecret is the canonical 192-byte secret key defined by xxHash3.
var defaultSecret = [secDefSize]byte{
	0xb8, 0xfe, 0x6c, 0x39, 0x23, 0xa4, 0x4b, 0xbe,
	0x7c, 0x01, 0x81, 0x2c, 0xf7, 0x21, 0xad, 0x1c,
	0xde, 0xd4, 0x6d, 0xfa, 0x9e, 0x21, 0x0b, 0xc5,
	0xac, 0x62, 0x07, 0x4c, 0x15, 0x54, 0x5a, 0x47,
	0x12, 0x60, 0x93, 0x65, 0x75, 0x2a, 0x49, 0x24,
	0xfa, 0x4f, 0x6c, 0xa0, 0x1e, 0xa7, 0x20, 0x7b,
	0x63, 0x13, 0x2a, 0xa8, 0x47, 0x14, 0x63, 0x17,
	0x6e, 0x8f, 0xb7, 0x9f, 0x49, 0x91, 0xc1, 0xa2,
	0xfa, 0xa6, 0x23, 0x49, 0x9b, 0x7e, 0xd1, 0x80,
	0x68, 0xb7, 0x10, 0x98, 0x32, 0xdc, 0x2d, 0xb9,
	0x55, 0x72, 0x79, 0xef, 0xeb, 0x76, 0x68, 0x3b,
	0x19, 0xef, 0x03, 0xbc, 0xfe, 0x75, 0xbe, 0xa0,
	0x5f, 0xc8, 0x6f, 0xb4, 0x92, 0x64, 0xdf, 0xc0,
	0x6e, 0x96, 0x26, 0x1d, 0xef, 0xdf, 0x96, 0xeb,
	0x89, 0xb2, 0xa9, 0xc8, 0xaa, 0x1e, 0xb3, 0x46,
	0x65, 0x02, 0x8a, 0x14, 0xd6, 0x9b, 0xd8, 0x44,
	0x81, 0x71, 0x46, 0x08, 0x37, 0x03, 0x73, 0x80,
	0x64, 0x61, 0xbf, 0x19, 0x5f, 0xd7, 0x85, 0x96,
	0xd7, 0xb7, 0x17, 0x39, 0x9e, 0x6a, 0xeb, 0x6c,
	0xb8, 0x6e, 0x48, 0x2f, 0x04, 0xb8, 0x71, 0x51,
	0x6e, 0x19, 0x1a, 0x89, 0xd1, 0x4a, 0xce, 0xe1,
	0x29, 0xd4, 0x58, 0xd7, 0x81, 0x1b, 0x09, 0x67,
	0x81, 0x66, 0x93, 0xa9, 0x44, 0x42, 0x8e, 0x9c,
	0x7f, 0x5f, 0xa4, 0x86, 0x5e, 0x95, 0x57, 0x6d,
}

// strToBytes converts string s to a byte slice without heap allocation.
func strToBytes(s string) []byte {
	if len(s) == 0 {
		return nil
	}
	return unsafe.Slice(unsafe.StringData(s), len(s))
}

// mul128Fold multiplies 64-bit integers x and y producing a 128-bit product
// and returns the XOR combination of the high and low 64-bit halves.
func mul128Fold(x, y uint64) uint64 {
	hi, lo := bits.Mul64(x, y)
	return hi ^ lo
}

// avalanche performs final bit mixing on h to ensure high bit diffusion.
func avalanche(h uint64) uint64 {
	h ^= h >> 37
	h *= prime64_3
	h ^= h >> 32
	return h
}

// avalanche64 mixes short inputs using the XXH64 avalanche constant.
func avalanche64(h uint64) uint64 {
	h ^= h >> 33
	h *= prime64_2
	h ^= h >> 29
	h *= prime64_3
	h ^= h >> 32
	return h
}

// rrmxmx applies the rrmxmx mix step on input word h and payload length l.
func rrmxmx(h, l uint64) uint64 {
	h ^= bits.RotateLeft64(h, 49) ^ bits.RotateLeft64(h, 24)
	h *= 0x9FB21C651E98DF25
	h ^= (h >> 35) + l
	h *= 0x9FB21C651E98DF25
	return h ^ (h >> 28)
}

// mix16B hashes a 16-byte chunk in against 16 bytes of secret sec and seed.
func mix16B(in, sec []byte, seed uint64) uint64 {
	_, _ = in[15], sec[15]
	inLo := binary.LittleEndian.Uint64(in[0:8])
	inHi := binary.LittleEndian.Uint64(in[8:16])
	secLo := binary.LittleEndian.Uint64(sec[0:8]) + seed
	secHi := binary.LittleEndian.Uint64(sec[8:16]) - seed
	return mul128Fold(inLo^secLo, inHi^secHi)
}

// initSec derives a custom secret buffer cSec from secret sec and 64-bit seed.
func initSec(sec []byte, seed uint64, cSec []byte) {
	_ = sec[secDefSize-1]
	_ = cSec[secDefSize-1]
	for i := 0; i < secDefSize; i += 16 {
		lo := binary.LittleEndian.Uint64(sec[i:i+8]) + seed
		hi := binary.LittleEndian.Uint64(sec[i+8:i+16]) - seed
		binary.LittleEndian.PutUint64(cSec[i:i+8], lo)
		binary.LittleEndian.PutUint64(cSec[i+8:i+16], hi)
	}
}

// hash64 dispatches byte slice b to the appropriate length hashing function.
func hash64(b, sec []byte, seed uint64) uint64 {
	n := len(b)
	switch {
	case n <= 16:
		return len0to16(b, sec, seed)
	case n <= 128:
		return len17to128(b, sec, seed)
	case n <= midSizeMax:
		return len129to240(b, sec, seed)
	default:
		return hashLong(b, sec)
	}
}

// len0to16 hashes payloads between 0 and 16 bytes in length.
func len0to16(b, sec []byte, seed uint64) uint64 {
	l := len(b)
	if l == 0 {
		sec7 := binary.LittleEndian.Uint64(sec[56:64])
		sec8 := binary.LittleEndian.Uint64(sec[64:72])
		return avalanche(sec7 ^ sec8 ^ seed)
	}
	if l <= 3 {
		c1 := b[0]
		c2 := b[l>>1]
		c3 := b[l-1]
		comb := (uint32(c1) << 16) |
			(uint32(c2) << 24) |
			(uint32(c3) << 8) |
			uint32(l)
		sec0 := binary.LittleEndian.Uint32(sec[0:4])
		sec1 := binary.LittleEndian.Uint32(sec[4:8])
		bf := (sec0 ^ sec1) + uint32(seed)
		return avalanche64(uint64(comb) ^ uint64(bf))
	}
	if l <= 8 {
		u1 := binary.LittleEndian.Uint32(b[0:4])
		u2 := binary.LittleEndian.Uint32(b[l-4 : l])
		in64 := uint64(u1) | (uint64(u2) << 32)
		sec1 := binary.LittleEndian.Uint64(sec[8:16])
		sec2 := binary.LittleEndian.Uint64(sec[16:24])
		bf := (sec1 ^ sec2) - seed
		return rrmxmx(in64^bf, uint64(l))
	}
	sec1 := binary.LittleEndian.Uint64(sec[24:32]) ^ seed
	sec2 := binary.LittleEndian.Uint64(sec[32:40]) - seed
	in1 := binary.LittleEndian.Uint64(b[0:8]) ^ sec1
	in2 := binary.LittleEndian.Uint64(b[l-8:l]) ^ sec2
	acc := uint64(l) + bits.RotateLeft64(in1, 49) +
		bits.RotateLeft64(in2, 24) + mul128Fold(in1, in2)
	return avalanche(acc)
}

// len17to128 hashes payloads between 17 and 128 bytes in length.
func len17to128(b, sec []byte, seed uint64) uint64 {
	l := len(b)
	_, _ = b[l-1], sec[127]
	acc := uint64(l) * prime64_1
	if l > 32 {
		if l > 64 {
			if l > 96 {
				acc += mix16B(b[48:64], sec[96:112], seed)
				acc += mix16B(b[l-64:l-48], sec[112:128], seed)
			}
			acc += mix16B(b[32:48], sec[64:80], seed)
			acc += mix16B(b[l-48:l-32], sec[80:96], seed)
		}
		acc += mix16B(b[16:32], sec[32:48], seed)
		acc += mix16B(b[l-32:l-16], sec[48:64], seed)
	}
	acc += mix16B(b[0:16], sec[0:16], seed)
	acc += mix16B(b[l-16:l], sec[16:32], seed)
	return avalanche(acc)
}

// len129to240 hashes payloads between 129 and 240 bytes in length.
func len129to240(b, sec []byte, seed uint64) uint64 {
	l := len(b)
	_, _ = b[l-1], sec[191]
	acc := uint64(l) * prime64_1
	rounds := l / 16
	for i := range 8 {
		acc += mix16B(b[16*i:16*i+16], sec[16*i:16*i+16], seed)
	}
	acc = avalanche(acc)
	for i := 8; i < rounds; i++ {
		acc += mix16B(b[16*i:16*i+16], sec[16*(i-8)+3:16*(i-8)+19], seed)
	}
	acc += mix16B(b[l-16:l], sec[192-17:192-1], seed)
	return avalanche(acc)
}

// hashLong hashes payloads longer than 240 bytes using stripe accumulation.
func hashLong(b, sec []byte) uint64 {
	var acc [8]uint64
	initAcc(&acc)
	accumulate(&acc, b, sec)
	return mergeAcc(&acc, sec, uint64(len(b)))
}

// initAcc initializes the 8 accumulator lanes with default xxHash3 primes.
func initAcc(acc *[8]uint64) {
	acc[0] = uint64(prime32_3)
	acc[1] = prime64_1
	acc[2] = prime64_2
	acc[3] = prime64_3
	acc[4] = prime64_4
	acc[5] = prime64_5
	acc[6] = uint64(prime32_1)
	acc[7] = uint64(prime32_2)
}

// accumulate processes byte slice b in 1024-byte blocks and 64-byte stripes.
func accumulate(acc *[8]uint64, b, sec []byte) {
	secLen := len(sec)
	stripesPerBlock := (secLen - stripeLen) / secStep

	bLen := stripesPerBlock * stripeLen
	numBlocks := len(b) / bLen

	for n := range numBlocks {
		block := b[n*bLen : (n+1)*bLen]
		for s := range stripesPerBlock {
			stripe := block[s*stripeLen : (s+1)*stripeLen]
			secStripe := sec[s*secStep : s*secStep+stripeLen]
			accumulateStripe(acc, stripe, secStripe)
		}
		scramble(acc, sec[secLen-stripeLen:])
	}

	remLen := len(b) - numBlocks*bLen
	numStripes := remLen / stripeLen
	remBytes := b[numBlocks*bLen:]
	for s := range numStripes {
		stripe := remBytes[s*stripeLen : (s+1)*stripeLen]
		secStripe := sec[s*secStep : s*secStep+stripeLen]
		accumulateStripe(acc, stripe, secStripe)
	}

	if remLen%stripeLen != 0 {
		lastStripe := b[len(b)-stripeLen:]
		secStripe := sec[secLen-stripeLen-7:]
		accumulateStripe(acc, lastStripe, secStripe)
	}
}

// accumulateStripe updates 8 accumulator lanes with 64 bytes of stripe data
// and 64 bytes of secret key using fully unrolled parallel lanes.
func accumulateStripe(acc *[8]uint64, stripe, sec []byte) {
	_ = stripe[63]
	_ = sec[63]

	in0 := binary.LittleEndian.Uint64(stripe[0:8])
	in1 := binary.LittleEndian.Uint64(stripe[8:16])
	in2 := binary.LittleEndian.Uint64(stripe[16:24])
	in3 := binary.LittleEndian.Uint64(stripe[24:32])
	in4 := binary.LittleEndian.Uint64(stripe[32:40])
	in5 := binary.LittleEndian.Uint64(stripe[40:48])
	in6 := binary.LittleEndian.Uint64(stripe[48:56])
	in7 := binary.LittleEndian.Uint64(stripe[56:64])

	sec0 := binary.LittleEndian.Uint64(sec[0:8])
	sec1 := binary.LittleEndian.Uint64(sec[8:16])
	sec2 := binary.LittleEndian.Uint64(sec[16:24])
	sec3 := binary.LittleEndian.Uint64(sec[24:32])
	sec4 := binary.LittleEndian.Uint64(sec[32:40])
	sec5 := binary.LittleEndian.Uint64(sec[40:48])
	sec6 := binary.LittleEndian.Uint64(sec[48:56])
	sec7 := binary.LittleEndian.Uint64(sec[56:64])

	dk0 := in0 ^ sec0
	dk1 := in1 ^ sec1
	dk2 := in2 ^ sec2
	dk3 := in3 ^ sec3
	dk4 := in4 ^ sec4
	dk5 := in5 ^ sec5
	dk6 := in6 ^ sec6
	dk7 := in7 ^ sec7

	acc[1] += in0
	acc[0] += uint64(uint32(dk0)) * uint64(dk0>>32)

	acc[0] += in1
	acc[1] += uint64(uint32(dk1)) * uint64(dk1>>32)

	acc[3] += in2
	acc[2] += uint64(uint32(dk2)) * uint64(dk2>>32)

	acc[2] += in3
	acc[3] += uint64(uint32(dk3)) * uint64(dk3>>32)

	acc[5] += in4
	acc[4] += uint64(uint32(dk4)) * uint64(dk4>>32)

	acc[4] += in5
	acc[5] += uint64(uint32(dk5)) * uint64(dk5>>32)

	acc[7] += in6
	acc[6] += uint64(uint32(dk6)) * uint64(dk6>>32)

	acc[6] += in7
	acc[7] += uint64(uint32(dk7)) * uint64(dk7>>32)
}

// scramble scrambles 8 accumulator lanes using secret sec at block boundary.
func scramble(acc *[8]uint64, sec []byte) {
	_ = sec[63]
	sec0 := binary.LittleEndian.Uint64(sec[0:8])
	sec1 := binary.LittleEndian.Uint64(sec[8:16])
	sec2 := binary.LittleEndian.Uint64(sec[16:24])
	sec3 := binary.LittleEndian.Uint64(sec[24:32])
	sec4 := binary.LittleEndian.Uint64(sec[32:40])
	sec5 := binary.LittleEndian.Uint64(sec[40:48])
	sec6 := binary.LittleEndian.Uint64(sec[48:56])
	sec7 := binary.LittleEndian.Uint64(sec[56:64])

	p := uint64(prime32_1)

	acc[0] = ((acc[0] ^ (acc[0] >> 47)) ^ sec0) * p
	acc[1] = ((acc[1] ^ (acc[1] >> 47)) ^ sec1) * p
	acc[2] = ((acc[2] ^ (acc[2] >> 47)) ^ sec2) * p
	acc[3] = ((acc[3] ^ (acc[3] >> 47)) ^ sec3) * p
	acc[4] = ((acc[4] ^ (acc[4] >> 47)) ^ sec4) * p
	acc[5] = ((acc[5] ^ (acc[5] >> 47)) ^ sec5) * p
	acc[6] = ((acc[6] ^ (acc[6] >> 47)) ^ sec6) * p
	acc[7] = ((acc[7] ^ (acc[7] >> 47)) ^ sec7) * p
}

// mergeAcc combines 8 accumulators into a final 64-bit checksum.
func mergeAcc(acc *[8]uint64, sec []byte, totalLen uint64) uint64 {
	_ = sec[74]
	res := totalLen * prime64_1
	res += mix2Accs(acc[0], acc[1], sec[11:27])
	res += mix2Accs(acc[2], acc[3], sec[27:43])
	res += mix2Accs(acc[4], acc[5], sec[43:59])
	res += mix2Accs(acc[6], acc[7], sec[59:75])
	return avalanche(res)
}

// mix2Accs mixes two 64-bit accumulator words with 16 bytes of secret sec.
func mix2Accs(acc1, acc2 uint64, sec []byte) uint64 {
	_ = sec[15]
	sec1 := binary.LittleEndian.Uint64(sec[0:8])
	sec2 := binary.LittleEndian.Uint64(sec[8:16])
	return mul128Fold(acc1^sec1, acc2^sec2)
}
