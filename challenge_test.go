//  @author: Brian Wojtczak
//  @copyright: 2024 by Brian Wojtczak
//  @license: BSD-style license found in the LICENSE file

package altcha

import (
	"math"
	"testing"
)

func TestNewChallenge(t *testing.T) {

	// Override randomInt and randomString for deterministic behavior
	randomInt = func(minimum, maximum int) int {
		return int(math.Ceil(float64(maximum-minimum) / 2))
	}
	randomString = func(length int) string {
		const fakeRandomString = "0V5xzYiSFmY1swbbkwIoAgbWaiw7yJvZ2L8ywAkUIgN3uSccMxKoCgdYdx9lLyXY"
		return fakeRandomString[:length]
	}
	RotateSecrets() // Rotate secrets so that the fake random string is used

	const want = `{"algorithm":"SHA-256","salt":"0V5xzYiSFmY1swbb","challenge":"69df4e03d8fffc1d66aeba60384ad28d70caed4bcf10c69f80e0a16666eae6a7","signature":"fa0cad0fa7b4aa33d9927b9dd3690eceaf0aaac6b27d77c62357b165716323a9"}`

	got := NewChallenge()

	if got != want {
		t.Errorf("NewChallenge() = %v, want %v", got, want)
	}
}

func TestNewChallengeWithParams(t *testing.T) {

	// Override randomInt and randomString for deterministic behavior
	randomInt = func(minimum, maximum int) int {
		return int(math.Ceil(float64(maximum-minimum) / 2))
	}
	randomString = func(length int) string {
		const fakeRandomString = "0V5xzYiSFmY1swbbkwIoAgbWaiw7yJvZ2L8ywAkUIgN3uSccMxKoCgdYdx9lLyXY"
		return fakeRandomString[:length]
	}
	RotateSecrets() // Rotate secrets so that the fake random string is used

	type args struct {
		params Parameters
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "SHA-256-34000",
			args: args{
				params: Parameters{
					Algorithm: "SHA-256",
					Number:    34000,
				},
			},
			want: `{"algorithm":"SHA-256","salt":"0V5xzYiSFmY1swbb","challenge":"7364dfc15e9cf0ab7d950dba7901144fcb88240e1b42f8581d3d1ddb41defe8a","signature":"3f75063475e2140836dd20afb878d94787ce751640a07f792452240343e1f36d"}`,
		},
		{
			name: "SHA-384-34000",
			args: args{
				params: Parameters{
					Algorithm: "SHA-384",
					Number:    34000,
				},
			},
			want: `{"algorithm":"SHA-384","salt":"0V5xzYiSFmY1swbb","challenge":"c2d1fcad24fc054bed3352d4531fa6092912ef4abd1caa6962123fb81fd6a4670b04bf432551081f233c0b4164f15a34","signature":"cbc670c92403af0d043b74046c8177c8db9bbf4397cfe484989da971805146b19e4825cbf4561a6dfe62190a4f3912db"}`,
		},
		{
			name: "SHA-512-34000",
			args: args{
				params: Parameters{
					Algorithm: "SHA-512",
					Number:    34000,
				},
			},
			want: `{"algorithm":"SHA-512","salt":"0V5xzYiSFmY1swbb","challenge":"46b8a27a0557814575bc70e78e4cf6515981c0b2012e3227745c09225cf096734fea3be283f4dac9f8d2f76c4af693f2d9217c3468e573b59279013a60fca64d","signature":"70dc17d9a83ec68c7d6eb17960f5bc2120649f641736283f52de9fdb125faae2f863e7b2d2029748f3c7fb823afa636ac4f999473a5ebe30bfd72f1f00e8b26c"}`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := NewChallengeWithParams(tt.args.params); got != tt.want {
				t.Errorf("NewChallengeWithParams() = %v, want %v", got, tt.want)
			}
		})
	}
}
