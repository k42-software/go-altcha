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

	const want = `{"algorithm":"SHA-256","salt":"0V5xzYiSFmY1swbb","challenge":"69df4e03d8fffc1d66aeba60384ad28d70caed4bcf10c69f80e0a16666eae6a7","signature":"-gytD6e0qjPZknud02kOzq8KqsayfXfGI1exZXFjI6k"}`

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
			want: `{"algorithm":"SHA-256","salt":"0V5xzYiSFmY1swbb","challenge":"7364dfc15e9cf0ab7d950dba7901144fcb88240e1b42f8581d3d1ddb41defe8a","signature":"P3UGNHXiFAg23SCvuHjZR4fOdRZAoH95JFIkA0Ph820"}`,
		},
		{
			name: "SHA-384-34000",
			args: args{
				params: Parameters{
					Algorithm: "SHA-384",
					Number:    34000,
				},
			},
			want: `{"algorithm":"SHA-384","salt":"0V5xzYiSFmY1swbb","challenge":"c2d1fcad24fc054bed3352d4531fa6092912ef4abd1caa6962123fb81fd6a4670b04bf432551081f233c0b4164f15a34","signature":"y8ZwySQDrw0EO3QEbIF3yNubv0OXz-SEmJ2pcYBRRrGeSCXL9FYabf5iGQpPORLb"}`,
		},
		{
			name: "SHA-512-34000",
			args: args{
				params: Parameters{
					Algorithm: "SHA-512",
					Number:    34000,
				},
			},
			want: `{"algorithm":"SHA-512","salt":"0V5xzYiSFmY1swbb","challenge":"46b8a27a0557814575bc70e78e4cf6515981c0b2012e3227745c09225cf096734fea3be283f4dac9f8d2f76c4af693f2d9217c3468e573b59279013a60fca64d","signature":"cNwX2ag-xox9brF5YPW8ISBkn2QXNig_Ut6f2xJfquL4Y-ey0gKXSPPH-4I6-mNqxPmZRzpevjC_1y8fAOiybA"}`,
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
