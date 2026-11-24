// External Secrets Operator for NAVER Cloud Platform
// Copyright (c) 2026-present NAVER Cloud Corp.
// Apache-2.0
package secretmanager

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	esv1 "github.com/external-secrets/external-secrets/apis/externalsecrets/v1"
)

func TestGetAllSecrets(t *testing.T) {
	server, client := setupTestServer(t)
	defer server.Close()

	tests := []struct {
		name    string
		ref     esv1.ExternalSecretFind
		wantLen int
		wantErr bool
		errIs   error
	}{
		{
			name:    "empty active stage fails the whole find",
			ref:     esv1.ExternalSecretFind{},
			wantErr: true,
			errIs:   ErrEmptySecretData,
		},
		{
			name: "filter by path",
			ref: esv1.ExternalSecretFind{
				Path: new("prod/"),
			},
			wantLen: 1,
			wantErr: false,
		},
		{
			name: "filter by name pattern",
			ref: esv1.ExternalSecretFind{
				Name: &esv1.FindName{
					RegExp: "secret1",
				},
			},
			wantLen: 1,
			wantErr: false,
		},
		{
			name: "tags not supported",
			ref: esv1.ExternalSecretFind{
				Tags: map[string]string{"env": "prod"},
			},
			wantErr: true,
			errIs:   ErrTagsNotSupported,
		},
		{
			name: "an empty tags map is no filter, as every other provider reads it",
			ref: esv1.ExternalSecretFind{
				Name: &esv1.FindName{RegExp: "secret1"},
				Tags: map[string]string{},
			},
			wantLen: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := client.GetAllSecrets(context.Background(), tt.ref)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetAllSecrets() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.errIs != nil && !errors.Is(err, tt.errIs) {
				t.Errorf("GetAllSecrets() error = %v, want errors.Is(%v)", err, tt.errIs)
			}
			if !tt.wantErr && len(got) != tt.wantLen {
				t.Errorf("GetAllSecrets() returned %d secrets, want %d", len(got), tt.wantLen)
			}
		})
	}
}

// TestGetAllSecretsRecoversAnEntryOneSweepMissed pins the third place this
// provider infers what is not there. GetAllSecrets hands ESO the map the Secret
// is rebuilt from, so an entry a sweep never saw is a key deleted from a live
// Secret, which the comment on GetAllSecrets already says out loud.
func TestGetAllSecretsRecoversAnEntryOneSweepMissed(t *testing.T) {
	sweep := 0
	mock := &countingMockClient{
		listFn: func(_ context.Context, pageNo int) (*NcloudListSecretsResponse, error) {
			if pageNo == 1 {
				sweep++
			}
			page := func(items ...NcloudSecretListItem) *NcloudListSecretsResponse {
				return &NcloudListSecretsResponse{
					Code: successCode,
					Data: NcloudListSecretsData{
						TotalPageNo: 2, CurrentPageNo: pageNo, TotalCount: 4, SecretList: items,
					},
				}
			}
			item := func(n string) NcloudSecretListItem {
				return NcloudSecretListItem{SecretID: testSecretID(n), SecretName: n, SecretStatus: secretStatusEnable}
			}
			// Sweep 1 never sees "beta": a delete on page 1 pulled it back into
			// a page already read, and a create elsewhere kept totalCount at 4.
			if sweep == 1 {
				if pageNo == 1 {
					return page(item("alpha"), item("gamma")), nil
				}
				return page(item("delta"), item("epsilon")), nil
			}
			if pageNo == 1 {
				return page(item("alpha"), item("beta")), nil
			}
			return page(item("delta"), item("epsilon")), nil
		},
		getSecretValueFn: func(_ context.Context, secretID string) (*NcloudSecretValueResponse, error) {
			return newSecretValueResponse(secretID), nil
		},
	}
	client := newMockedClient(mock)

	all, err := client.GetAllSecrets(context.Background(), esv1.ExternalSecretFind{
		Name: &esv1.FindName{RegExp: ".*"},
	})
	if err != nil {
		t.Fatalf("GetAllSecrets() error = %v", err)
	}
	if _, ok := all["beta"]; !ok {
		t.Errorf("GetAllSecrets() dropped %q, which only the second sweep saw; got keys %v",
			"beta", slices.Sorted(maps.Keys(all)))
	}
	// The union keeps what either sweep saw, so gamma survives too even though
	// the second sweep no longer lists it. Its value read is what settles
	// whether it is really there.
	if _, ok := all["gamma"]; !ok {
		t.Errorf("GetAllSecrets() dropped %q, which only the first sweep saw", "gamma")
	}
}

// TestGetAllSecretsSurvivesANameRecreatedUnderANewID: a name deleted and
// recreated between two sweeps must resolve to the live secret. The consumer
// dedups by name and marks the name seen BEFORE reading the value, so a stale
// entry left in front of a live one burns the name on a read that then 404s,
// and the live secret behind it is never read at all.
func TestGetAllSecretsSurvivesANameRecreatedUnderANewID(t *testing.T) {
	const (
		oldID = "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1"
		newID = "b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2"
	)
	sweep := 0
	mock := &countingMockClient{
		listFn: func(_ context.Context, pageNo int) (*NcloudListSecretsResponse, error) {
			if pageNo == 1 {
				sweep++
			}
			page := func(items ...NcloudSecretListItem) *NcloudListSecretsResponse {
				return &NcloudListSecretsResponse{
					Code: successCode,
					Data: NcloudListSecretsData{
						TotalPageNo: 2, CurrentPageNo: pageNo, TotalCount: 2, SecretList: items,
					},
				}
			}
			filler := NcloudSecretListItem{
				SecretID:   "f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0",
				SecretName: "filler", SecretStatus: secretStatusEnable,
			}
			id := newID
			if sweep == 1 {
				// Before the recreate: the name resolves to the old secret.
				id = oldID
			}
			if pageNo == 1 {
				return page(NcloudSecretListItem{
					SecretID: id, SecretName: "db-cred", SecretStatus: secretStatusEnable,
				}), nil
			}
			return page(filler), nil
		},
		getSecretValueFn: func(_ context.Context, secretID string) (*NcloudSecretValueResponse, error) {
			// The old secret is gone by the time any value is read, which is
			// what makes the stale entry poisonous rather than merely useless.
			if secretID == oldID {
				return nil, ErrSecretNotFound
			}
			return newSecretValueResponse("fresh"), nil
		},
	}
	client := newMockedClient(mock)

	all, err := client.GetAllSecrets(context.Background(), esv1.ExternalSecretFind{
		Name: &esv1.FindName{RegExp: "db-cred"},
	})
	if err != nil {
		t.Fatalf("GetAllSecrets() error = %v", err)
	}
	if got := string(all["db-cred"]); got != "fresh" {
		t.Errorf("GetAllSecrets()[db-cred] = %q, want %q; the stale entry took the name and the live secret was skipped",
			got, "fresh")
	}
}

// TestGetAllSecretsKeepsABystanderThroughANameTakeoverAndADuplicate: a secret
// nothing happened to must keep its name when another secret is listed under
// that name in one sweep and under another name in the confirming sweep, in
// either order, as a name changing hands between the sweeps can list. Such a
// change moves no count, so no stability gate sees it; only the merge order
// can get this right or wrong. Within one sweep the same change lists an ID
// twice, which fails the sweep instead (see listSweep.incomplete).
func TestGetAllSecretsKeepsABystanderThroughANameTakeoverAndADuplicate(t *testing.T) {
	const (
		idX = "aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111"
		idY = "bbbb2222bbbb2222bbbb2222bbbb2222bbbb2222bbbb2222bbbb2222bbbb2222"
	)
	item := func(id, name string) NcloudSecretListItem {
		return NcloudSecretListItem{SecretID: id, SecretName: name, SecretStatus: secretStatusEnable}
	}
	// X is listed under n1 in one sweep and under n2 in the other, and Y
	// independently holds n1 as a duplicate, on the second of two pages. Both
	// orders of the two sweeps must agree.
	for _, tc := range []struct {
		name   string
		sweeps [2][]NcloudSecretListItem
	}{
		{name: "the second name lands last", sweeps: [2][]NcloudSecretListItem{
			{item(idX, "n1"), item(idY, "n1")}, {item(idX, "n2"), item(idY, "n1")},
		}},
		{name: "the second name lands first", sweeps: [2][]NcloudSecretListItem{
			{item(idX, "n2"), item(idY, "n1")}, {item(idX, "n1"), item(idY, "n1")},
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sweep := 0
			mock := &countingMockClient{
				listFn: func(_ context.Context, pageNo int) (*NcloudListSecretsResponse, error) {
					if pageNo == 1 && sweep < len(tc.sweeps) {
						sweep++
					}
					rows := tc.sweeps[sweep-1]
					return &NcloudListSecretsResponse{
						Code: successCode,
						Data: NcloudListSecretsData{
							TotalPageNo: 2, CurrentPageNo: pageNo, TotalCount: 2, SecretList: rows[pageNo-1 : pageNo],
						},
					}, nil
				},
				getSecretValueFn: func(_ context.Context, secretID string) (*NcloudSecretValueResponse, error) {
					return newSecretValueResponse(secretID), nil
				},
			}
			client := newMockedClient(mock)

			all, err := client.GetAllSecrets(context.Background(), esv1.ExternalSecretFind{
				Name: &esv1.FindName{RegExp: ".*"},
			})
			if err != nil {
				t.Fatalf("GetAllSecrets() error = %v", err)
			}
			// n1 is claimed by whichever row reached it first; what must not
			// happen is n1 disappearing because X's later row no longer holds it.
			if _, ok := all["n1"]; !ok {
				t.Errorf("GetAllSecrets() dropped n1 entirely; got %v", slices.Sorted(maps.Keys(all)))
			}
			if _, ok := all["n2"]; !ok {
				t.Errorf("GetAllSecrets() dropped n2; got %v", slices.Sorted(maps.Keys(all)))
			}
		})
	}
}

// TestGetAllSecretsSkipsATombstoneInFrontOfTheLiveName pins the one rule the
// per-sweep dedup and the consumer have to share: a lifecycle tombstone does
// not claim a name. The provider manufactures this state itself - DeleteSecret
// leaves a secret in REVOKE for up to seven days and createSecretLocked treats
// that name as free - so a delete followed by a push of the same key lists the
// tombstone and the live secret together, in whatever order the server returns
// them. Deduping the pair status-blind hands the name to the tombstone, which
// the consumer then skips, and the live secret leaves GetAllSecrets with a nil
// error. ESO rewrites the managed Secret from that map, so the key is deleted.
func TestGetAllSecretsSkipsATombstoneInFrontOfTheLiveName(t *testing.T) {
	const (
		tombstone = "dddd0000dddd0000dddd0000dddd0000dddd0000dddd0000dddd0000dddd0000"
		live      = "eeee1111eeee1111eeee1111eeee1111eeee1111eeee1111eeee1111eeee1111"
		bystander = "ffff2222ffff2222ffff2222ffff2222ffff2222ffff2222ffff2222ffff2222"
	)
	// Both orderings, because they fail in different places: the tombstone
	// first has to lose the per-sweep name claim, the tombstone last has to
	// stay out of the cross-sweep name index it would otherwise overwrite.
	for _, dead := range []string{secretStatusRevoke, secretStatusDestroyed} {
		for _, tombstoneFirst := range []bool{true, false} {
			order := "the tombstone is listed last"
			if tombstoneFirst {
				order = "the tombstone is listed first"
			}
			t.Run(dead+", "+order, func(t *testing.T) {
				deadRow := NcloudSecretListItem{SecretID: tombstone, SecretName: "dup", SecretStatus: dead}
				liveRow := NcloudSecretListItem{SecretID: live, SecretName: "dup", SecretStatus: secretStatusEnable}
				rows := make([]NcloudSecretListItem, 0, 3)
				if tombstoneFirst {
					rows = append(rows, deadRow, liveRow)
				} else {
					rows = append(rows, liveRow, deadRow)
				}
				rows = append(rows, NcloudSecretListItem{
					SecretID: bystander, SecretName: "keep", SecretStatus: secretStatusEnable,
				})
				newClient := func() *Client {
					return newMockedClient(&countingMockClient{
						listFn: func(_ context.Context, pageNo int) (*NcloudListSecretsResponse, error) {
							return &NcloudListSecretsResponse{
								Code: successCode,
								Data: NcloudListSecretsData{
									TotalPageNo: 1, CurrentPageNo: pageNo, TotalCount: 3, SecretList: rows,
								},
							}, nil
						},
						getSecretValueFn: func(_ context.Context, secretID string) (*NcloudSecretValueResponse, error) {
							return newSecretValueResponse(secretID), nil
						},
					})
				}

				all, err := newClient().GetAllSecrets(context.Background(), esv1.ExternalSecretFind{
					Name: &esv1.FindName{RegExp: ".*"},
				})
				if err != nil {
					t.Fatalf("GetAllSecrets() error = %v", err)
				}
				if got := string(all["dup"]); got != live {
					t.Errorf("GetAllSecrets()[dup] = %q, want the live secret %s; got keys %v",
						got, live, slices.Sorted(maps.Keys(all)))
				}
				if _, ok := all["keep"]; !ok {
					t.Errorf("GetAllSecrets() dropped the bystander; got keys %v", slices.Sorted(maps.Keys(all)))
				}

				// The same listing read one secret at a time must agree. A find
				// that answers a name differently from a read of that name is the
				// same silent-omission bug seen from the other side.
				one, err := newClient().GetSecret(context.Background(), esv1.ExternalSecretDataRemoteRef{Key: "dup"})
				if err != nil {
					t.Fatalf("GetSecret(dup) error = %v", err)
				}
				if !bytes.Equal(one, all["dup"]) {
					t.Errorf("GetSecret(dup) = %q but GetAllSecrets reported %q", one, all["dup"])
				}
			})
		}
	}
}

func TestGetAllSecretsFailsOnForbiddenEvenAfterPartialReads(t *testing.T) {
	list := &NcloudListSecretsResponse{
		Code: successCode,
		Data: NcloudListSecretsData{
			TotalPageNo: 1,
			SecretList: []NcloudSecretListItem{
				{SecretID: testSecretID("ok"), SecretName: "ok"},
				{SecretID: testGoneSecretID, SecretName: "gone"},
				{SecretID: testSecretID("denied"), SecretName: "denied"},
			},
		},
	}
	mock := &countingMockClient{
		listFn: func(_ context.Context, _ int) (*NcloudListSecretsResponse, error) {
			return list, nil
		},
		getSecretValueFn: func(_ context.Context, secretID string) (*NcloudSecretValueResponse, error) {
			switch secretID {
			case testGoneSecretID:
				return nil, fmt.Errorf("%w: deleted mid-listing", ErrSecretNotFound)
			case testSecretID("denied"):
				return nil, fmt.Errorf("%w: key lacks access", ErrForbidden)
			default:
				return newSecretValueResponse("v"), nil
			}
		},
	}
	client := &Client{client: mock, cache: newSecretIDCache(time.Hour, time.Minute)}

	got, err := client.GetAllSecrets(context.Background(), esv1.ExternalSecretFind{})
	if !errors.Is(err, ErrForbidden) {
		t.Fatalf("GetAllSecrets() error = %v, want ErrForbidden", err)
	}
	if got != nil {
		t.Errorf("GetAllSecrets() returned a partial result on Forbidden: %v", got)
	}
}

func TestGetAllSecretsSkipsOnlyNotFoundRace(t *testing.T) {
	mock := &countingMockClient{
		listFn: listingWith(
			NcloudSecretListItem{SecretID: testSecretID("ok"), SecretName: "ok"},
			NcloudSecretListItem{SecretID: testGoneSecretID, SecretName: "gone"},
		),
		getSecretValueFn: func(_ context.Context, secretID string) (*NcloudSecretValueResponse, error) {
			if secretID == testGoneSecretID {
				return nil, fmt.Errorf("%w: deleted mid-listing", ErrSecretNotFound)
			}
			return newSecretValueResponse(testSecretObjectJSON), nil
		},
	}
	client := newMockedClient(mock)

	got, err := client.GetAllSecrets(context.Background(), esv1.ExternalSecretFind{})
	if err != nil {
		t.Fatalf("GetAllSecrets() error = %v, want NotFound race skipped", err)
	}
	if len(got) != 1 || string(got["ok"]) != testSecretObjectJSON {
		t.Errorf("GetAllSecrets() = %v, want only readable secret", got)
	}
}

func TestGetAllSecretsSkipsDeletionLifecycleStatuses(t *testing.T) {
	mock := &countingMockClient{
		listFn: listingWith(
			NcloudSecretListItem{SecretID: testSecretID("live"), SecretName: "live", SecretStatus: secretStatusEnable},
			NcloudSecretListItem{SecretID: testSecretID("revoke"), SecretName: "revoked", SecretStatus: secretStatusRevoke},
			NcloudSecretListItem{SecretID: testSecretID("destroyed"), SecretName: "destroyed", SecretStatus: secretStatusDestroyed},
		),
		getSecretValueFn: func(_ context.Context, secretID string) (*NcloudSecretValueResponse, error) {
			if secretID != testSecretID("live") {
				t.Fatalf("GetSecretValue(%q) called for deletion lifecycle item", secretID)
			}
			return newSecretValueResponse(testSecretObjectJSON), nil
		},
	}
	client := newMockedClient(mock)

	got, err := client.GetAllSecrets(context.Background(), esv1.ExternalSecretFind{})
	if err != nil {
		t.Fatalf("GetAllSecrets() error = %v", err)
	}
	if len(got) != 1 || string(got["live"]) != testSecretObjectJSON {
		t.Errorf("GetAllSecrets() = %v, want only live secret", got)
	}
	if mock.getSecretValueCalls != 1 {
		t.Errorf("GetSecretValue calls = %d, want 1", mock.getSecretValueCalls)
	}
	if id, found, negative := client.cache.Get("destroyed"); found && !negative {
		t.Errorf("destroyed mapping cached as live: %q", id)
	}
}

func TestGetAllSecretsReadsRotatingStatus(t *testing.T) {
	mock := &countingMockClient{
		listFn: listingWith(NcloudSecretListItem{
			SecretID: testSecretID("rotating"), SecretName: "rotating", SecretStatus: secretStatusRotating,
		}),
		getSecretValueFn: func(_ context.Context, secretID string) (*NcloudSecretValueResponse, error) {
			if secretID != testSecretID("rotating") {
				t.Fatalf("GetSecretValue() ID = %q, want rotating-id", secretID)
			}
			return newSecretValueResponse(`{"value":"active"}`), nil
		},
	}
	client := newMockedClient(mock)

	got, err := client.GetAllSecrets(context.Background(), esv1.ExternalSecretFind{})
	if err != nil {
		t.Fatalf("GetAllSecrets() error = %v", err)
	}
	if len(got) != 1 || string(got["rotating"]) != `{"value":"active"}` {
		t.Errorf("GetAllSecrets() = %v, want readable ROTATING secret", got)
	}
}

func TestGetAllSecretsSkipsInvalidStatusRaceAfterLifecycleConfirmation(t *testing.T) {
	// Both shapes the service gives a lifecycle-blocked value read (see
	// deletionLifecycleCandidate): 409, and 400 with code 501007.
	for name, raceErr := range map[string]error{
		"409":             fmt.Errorf("%w: lifecycle changed after listing", ErrInvalidStatus),
		"400 code 501007": newAPIError(ErrInvalidRequest, http.StatusBadRequest, "501007"),
	} {
		t.Run(name, func(t *testing.T) {
			mock := &countingMockClient{
				listFn: listingWith(
					NcloudSecretListItem{SecretID: testSecretID("live"), SecretName: "live", SecretStatus: secretStatusEnable},
					NcloudSecretListItem{SecretID: testSecretID("racing"), SecretName: "racing", SecretStatus: secretStatusEnable},
				),
				getSecretValueFn: func(_ context.Context, secretID string) (*NcloudSecretValueResponse, error) {
					if secretID == testSecretID("racing") {
						return nil, raceErr
					}
					return newSecretValueResponse(testSecretObjectJSON), nil
				},
				getSecretDetailFn: func(_ context.Context, secretID string) (*NcloudSecretDetailResponse, error) {
					if secretID != testSecretID("racing") {
						t.Fatalf("GetSecretDetail(%q), want racing-id", secretID)
					}
					return &NcloudSecretDetailResponse{
						Code: successCode,
						Data: NcloudSecretDetailData{SecretID: secretID, SecretStatus: secretStatusRevoke},
					}, nil
				},
			}
			client := newMockedClient(mock)

			got, err := client.GetAllSecrets(context.Background(), esv1.ExternalSecretFind{})
			if err != nil {
				t.Fatalf("GetAllSecrets() error = %v", err)
			}
			if len(got) != 1 || string(got["live"]) != testSecretObjectJSON {
				t.Errorf("GetAllSecrets() = %v, want detail-confirmed lifecycle item skipped", got)
			}
		})
	}
}

// TestGetAllSecretsSkipsWhenDetailConfirmsGone covers the other confirmation a
// lifecycle re-read can give: the secret is no longer there at all. Like a
// confirmed REVOKE/DESTROYED that is a skip, not a failure, because no value
// remains to preserve.
func TestGetAllSecretsSkipsWhenDetailConfirmsGone(t *testing.T) {
	mock := &countingMockClient{
		listFn: listingWith(
			NcloudSecretListItem{SecretID: testSecretID("live"), SecretName: "live", SecretStatus: secretStatusEnable},
			NcloudSecretListItem{SecretID: testGoneSecretID, SecretName: "gone", SecretStatus: secretStatusEnable},
		),
		getSecretValueFn: func(_ context.Context, secretID string) (*NcloudSecretValueResponse, error) {
			if secretID == testGoneSecretID {
				return nil, fmt.Errorf("%w: lifecycle changed after listing", ErrInvalidStatus)
			}
			return newSecretValueResponse(testSecretObjectJSON), nil
		},
		getSecretDetailFn: func(_ context.Context, _ string) (*NcloudSecretDetailResponse, error) {
			return nil, fmt.Errorf("%w: destroyed between calls", ErrSecretNotFound)
		},
	}
	client := newMockedClient(mock)

	got, err := client.GetAllSecrets(context.Background(), esv1.ExternalSecretFind{})
	if err != nil {
		t.Fatalf("GetAllSecrets() error = %v, want the vanished secret skipped", err)
	}
	if len(got) != 1 || string(got["live"]) != testSecretObjectJSON {
		t.Errorf("GetAllSecrets() = %v, want only live", got)
	}
}

func TestGetAllSecretsInvalidStatusRaceFailsClosed(t *testing.T) {
	for _, tc := range []struct {
		name     string
		detailFn func(context.Context, string) (*NcloudSecretDetailResponse, error)
	}{
		{
			name:     "detail remains ENABLE",
			detailFn: detailWithStatus(secretStatusEnable),
		},
		{
			name: "detail read fails",
			detailFn: func(_ context.Context, _ string) (*NcloudSecretDetailResponse, error) {
				return nil, fmt.Errorf("%w: detail unavailable", ErrServiceUnavailable)
			},
		},
		{
			name:     "detail has unknown status",
			detailFn: detailWithStatus("UNKNOWN"),
		},
		{
			// A nil detail with no error proves nothing about the lifecycle, so it
			// must not be read as "entered deletion".
			name: "detail response is empty",
			detailFn: func(_ context.Context, _ string) (*NcloudSecretDetailResponse, error) {
				return nil, nil
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mock := &countingMockClient{
				listFn: listingWith(
					NcloudSecretListItem{SecretID: testSecretID("ok"), SecretName: "ok", SecretStatus: secretStatusEnable},
					NcloudSecretListItem{SecretID: testSecretID("bad"), SecretName: "bad", SecretStatus: secretStatusEnable},
				),
				getSecretValueFn: func(_ context.Context, secretID string) (*NcloudSecretValueResponse, error) {
					if secretID == testSecretID("bad") {
						return nil, fmt.Errorf("%w: value unavailable", ErrInvalidStatus)
					}
					return newSecretValueResponse(testSecretObjectJSON), nil
				},
				getSecretDetailFn: tc.detailFn,
			}
			client := newMockedClient(mock)

			got, err := client.GetAllSecrets(context.Background(), esv1.ExternalSecretFind{})
			if !errors.Is(err, ErrInvalidStatus) {
				t.Fatalf("GetAllSecrets() error = %v, want original ErrInvalidStatus", err)
			}
			if got != nil {
				t.Errorf("GetAllSecrets() returned partial result: %v", got)
			}
		})
	}
}

// TestGetAllSecretsIgnoresUnreadableStatusOutsideSelector pins the documented
// way out of a wedged find: an unreadable secret only fails the operation when
// the selector actually matches it, so narrowing path/name.regexp lets the
// remaining secrets sync.
func TestGetAllSecretsIgnoresUnreadableStatusOutsideSelector(t *testing.T) {
	pattern := "^keep-"
	for _, status := range []string{secretStatusDisable, "UNKNOWN"} {
		t.Run(status, func(t *testing.T) {
			mock := &countingMockClient{
				listFn: listingWith(
					NcloudSecretListItem{SecretID: testSecretID("keep"), SecretName: "keep-me", SecretStatus: secretStatusEnable},
					NcloudSecretListItem{SecretID: testSecretID("other"), SecretName: "other", SecretStatus: status},
				),
				getSecretValueFn: func(_ context.Context, secretID string) (*NcloudSecretValueResponse, error) {
					if secretID != testSecretID("keep") {
						t.Errorf("GetSecretValue(%q): an unselected %s secret must not be read", secretID, status)
					}
					return newSecretValueResponse(testSecretObjectJSON), nil
				},
			}
			client := newMockedClient(mock)

			got, err := client.GetAllSecrets(context.Background(), esv1.ExternalSecretFind{
				Name: &esv1.FindName{RegExp: pattern},
			})
			if err != nil {
				t.Fatalf("GetAllSecrets() error = %v, want the unselected %s secret ignored", err, status)
			}
			if len(got) != 1 || string(got["keep-me"]) != testSecretObjectJSON {
				t.Errorf("GetAllSecrets() = %v, want only keep-me", got)
			}
		})
	}
}

func TestGetAllSecretsRejectsNonReadableListStatuses(t *testing.T) {
	for _, status := range []string{secretStatusDisable, "UNKNOWN"} {
		t.Run(status, func(t *testing.T) {
			mock := &countingMockClient{
				listFn: listingWith(NcloudSecretListItem{
					SecretID: testSecretID("bad"), SecretName: "bad", SecretStatus: status,
				}),
				getSecretValueFn: func(_ context.Context, secretID string) (*NcloudSecretValueResponse, error) {
					t.Fatalf("GetSecretValue(%q) called for status %s", secretID, status)
					return nil, nil
				},
			}
			client := newMockedClient(mock)

			got, err := client.GetAllSecrets(context.Background(), esv1.ExternalSecretFind{})
			if !errors.Is(err, ErrInvalidStatus) {
				t.Fatalf("GetAllSecrets() error = %v, want ErrInvalidStatus", err)
			}
			if got != nil {
				t.Errorf("GetAllSecrets() returned partial result: %v", got)
			}
		})
	}
}

func TestGetAllSecretsFailsOnTransientError(t *testing.T) {
	mock := &countingMockClient{
		listFn: func(_ context.Context, _ int) (*NcloudListSecretsResponse, error) {
			return &NcloudListSecretsResponse{
				Code: successCode,
				Data: NcloudListSecretsData{
					TotalPageNo: 1,
					SecretList:  []NcloudSecretListItem{{SecretID: testSecretID("x"), SecretName: "s"}},
				},
			}, nil
		},
		getSecretValueFn: func(_ context.Context, _ string) (*NcloudSecretValueResponse, error) {
			return nil, fmt.Errorf("%w: upstream flake", ErrServiceUnavailable)
		},
	}
	client := &Client{client: mock, cache: newSecretIDCache(time.Hour, time.Minute)}

	if _, err := client.GetAllSecrets(context.Background(), esv1.ExternalSecretFind{}); err == nil {
		t.Fatal("GetAllSecrets() must fail on transient errors instead of returning partial data")
	}
}

// TestListingPageDecodeRefusesWhatCannotBeAListing pins the two refusals of
// the row-by-row page decode: more rows than a page can carry, and a row
// whose ID is not in the form the API issues. Both fail the decode rather
// than skip rows, so a sweep concludes nothing about any name.
func TestListingPageDecodeRefusesWhatCannotBeAListing(t *testing.T) {
	row := func(id string) string {
		return `{"secretId":"` + id + `","secretName":"db-cred","secretStatus":"ENABLE"}`
	}
	page := func(rows ...string) []byte {
		return []byte(`{"code":"SUCCESS","data":{"totalPageNo":1,"currentPageNo":1,"totalCount":` +
			fmt.Sprint(len(rows)) + `,"secretList":[` + strings.Join(rows, ",") + `]}}`)
	}

	full := make([]string, maxListRowsPerPage, maxListRowsPerPage+1)
	for i := range full {
		full[i] = row(testSecretID(fmt.Sprint(i)))
	}
	var resp NcloudListSecretsResponse
	if err := json.Unmarshal(page(full...), &resp); err != nil || len(resp.Data.SecretList) != maxListRowsPerPage {
		t.Fatalf("a page of %d rows: err = %v, rows = %d", maxListRowsPerPage, err, len(resp.Data.SecretList))
	}
	if err := json.Unmarshal(page(append(full, row(testSecretID("one more")))...), &resp); err == nil ||
		!strings.Contains(err.Error(), fmt.Sprint(maxListRowsPerPage)) {
		t.Errorf("a page of %d rows: err = %v, want a refusal naming the cap", maxListRowsPerPage+1, err)
	}

	for _, id := range []string{"", "..", ".", "id", strings.Repeat("a", 64) + "b", strings.ToUpper(testSecretID("x"))} {
		err := json.Unmarshal(page(row(testSecretID("fine")), row(id)), &resp)
		if !errors.Is(err, ErrSecretIDMalformed) {
			t.Errorf("row with id %.20q: err = %v, want ErrSecretIDMalformed", id, err)
		}
	}

	if err := json.Unmarshal([]byte(`{"code":"SUCCESS","data":{"totalPageNo":1,"secretList":null}}`), &resp); err != nil || resp.Data.SecretList != nil {
		t.Errorf("null secretList: err = %v, rows = %v; want no rows and no error", err, resp.Data.SecretList)
	}

	// The protection key listing is decoded the same way: it is the other
	// array a response can fill with empty objects.
	keys := make([]string, maxListRowsPerPage+1)
	for i := range keys {
		keys[i] = `{"keyTag":"k","keyName":"n","keyStatus":"ENABLE"}`
	}
	var keyResp NcloudProtectionKeyListResponse
	body := []byte(`{"code":"SUCCESS","data":{"keyList":[` + strings.Join(keys, ",") + `]}}`)
	if err := json.Unmarshal(body, &keyResp); err == nil || !strings.Contains(err.Error(), fmt.Sprint(maxListRowsPerPage)) {
		t.Errorf("a key list of %d rows: err = %v, want a refusal naming the cap", len(keys), err)
	}
	body = []byte(`{"code":"SUCCESS","data":{"keyList":[` + strings.Join(keys[:3], ",") + `]}}`)
	if err := json.Unmarshal(body, &keyResp); err != nil || len(keyResp.Data.KeyList) != 3 {
		t.Errorf("a key list of 3 rows: err = %v, rows = %d", err, len(keyResp.Data.KeyList))
	}
}

// TestSweepStopsPastTheRowCap pins that rows accumulated across pages are
// bounded even when every page is within its own cap.
func TestSweepStopsPastTheRowCap(t *testing.T) {
	rows := make([]NcloudSecretListItem, maxListRowsPerPage)
	for i := range rows {
		rows[i] = NcloudSecretListItem{SecretID: testSecretID(fmt.Sprint(i)), SecretName: "other", SecretStatus: secretStatusEnable}
	}
	mock := &countingMockClient{
		listFn: func(_ context.Context, pageNo int) (*NcloudListSecretsResponse, error) {
			return &NcloudListSecretsResponse{Code: successCode, Data: NcloudListSecretsData{
				TotalPageNo: maxListPages, CurrentPageNo: pageNo, TotalCount: maxListPages * len(rows), SecretList: rows,
			}}, nil
		},
	}
	client := newMockedClient(mock)

	_, err := client.GetAllSecrets(context.Background(), esv1.ExternalSecretFind{Name: &esv1.FindName{RegExp: "^db-cred$"}})
	if err == nil || !strings.Contains(err.Error(), fmt.Sprint(maxListRows)) {
		t.Fatalf("GetAllSecrets() error = %v, want the row cap named", err)
	}
	if pages := maxListRows/len(rows) + 1; mock.listCalls > pages {
		t.Errorf("ListSecrets calls = %d, want at most %d before the cap", mock.listCalls, pages)
	}

	mock.listCalls = 0
	if _, err := client.GetSecret(context.Background(), esv1.ExternalSecretDataRemoteRef{Key: "db-cred"}); err == nil ||
		errors.Is(err, esv1.NoSecretErr) || !strings.Contains(err.Error(), fmt.Sprint(maxListRows)) {
		t.Errorf("GetSecret() error = %v, want the row cap named and not an absence", err)
	}
}

// TestSweepStopsPastItsBudget pins the wall-clock bound on one sweep: a
// server that answers every page slowly, with a page count to match, is cut
// off after maxSweepElapsed with an error that names the budget, and the
// caller's own context is untouched.
func TestSweepStopsPastItsBudget(t *testing.T) {
	previous := maxSweepElapsed
	maxSweepElapsed = 60 * time.Millisecond
	t.Cleanup(func() { maxSweepElapsed = previous })

	mock := &countingMockClient{
		listFn: func(ctx context.Context, pageNo int) (*NcloudListSecretsResponse, error) {
			select {
			case <-time.After(20 * time.Millisecond):
			case <-ctx.Done():
				return nil, ctx.Err()
			}
			return &NcloudListSecretsResponse{Code: successCode, Data: NcloudListSecretsData{
				TotalPageNo: maxListPages, CurrentPageNo: pageNo, TotalCount: maxListPages,
				SecretList: []NcloudSecretListItem{{SecretID: testSecretID(fmt.Sprint(pageNo)), SecretName: "other", SecretStatus: secretStatusEnable}},
			}}, nil
		},
	}
	client := newMockedClient(mock)
	ctx := context.Background()

	for name, call := range map[string]func() error{
		"read": func() error {
			_, err := client.GetSecret(ctx, esv1.ExternalSecretDataRemoteRef{Key: "db-cred"})
			return err
		},
		"find": func() error {
			_, err := client.GetAllSecrets(ctx, esv1.ExternalSecretFind{Name: &esv1.FindName{RegExp: ".*"}})
			return err
		},
		"write index": func() error {
			_, err := client.SecretExists(ctx, mockPushSecretRemoteRef{remoteKey: "db-cred"})
			return err
		},
	} {
		t.Run(name, func(t *testing.T) {
			mock.listCalls = 0
			err := call()
			if err == nil || errors.Is(err, esv1.NoSecretErr) || !errors.Is(err, context.DeadlineExceeded) ||
				!strings.Contains(err.Error(), "budget") {
				t.Fatalf("error = %v, want the sweep budget named and no absence", err)
			}
			if mock.listCalls > 10 {
				t.Errorf("ListSecrets calls = %d, want the sweep cut off within a few pages", mock.listCalls)
			}
			if ctx.Err() != nil {
				t.Errorf("the caller's context was canceled: %v", ctx.Err())
			}
		})
	}
}

// TestFindNamesAnUnrecognizedNameSafely pins that a server-supplied name the
// API would not have accepted is quoted and cut short in the find error, so a
// listing row cannot push kilobytes or terminal escapes into the controller
// log. Every error the find builds from a row's name is covered: a paused
// row, and a live row whose active stage is empty, which names the secret
// twice.
func TestFindNamesAnUnrecognizedNameSafely(t *testing.T) {
	hostile := "A\n\x1b[31mINJECTED" + strings.Repeat("x", 300)
	for _, tc := range []struct {
		name   string
		status string
		value  func(context.Context, string) (*NcloudSecretValueResponse, error)
	}{
		{name: "paused row", status: secretStatusDisable},
		{
			name:   "live row with an empty active stage",
			status: secretStatusEnable,
			value: func(context.Context, string) (*NcloudSecretValueResponse, error) {
				return newSecretValueResponse(""), nil
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mock := &countingMockClient{
				listFn:           listingWith(NcloudSecretListItem{SecretID: testSecretID("h"), SecretName: hostile, SecretStatus: tc.status}),
				getSecretValueFn: tc.value,
			}
			client := newMockedClient(mock)

			_, err := client.GetAllSecrets(context.Background(), esv1.ExternalSecretFind{Name: &esv1.FindName{RegExp: ".*"}})
			if err == nil {
				t.Fatal("GetAllSecrets() = nil error, want the row to fail the find")
			}
			if got := err.Error(); len(got) > 200 || strings.Contains(got, "\x1b") || strings.Contains(got, "\n") {
				t.Errorf("error = %q (%d bytes), want the name quoted and cut short", got, len(got))
			}
		})
	}
}
