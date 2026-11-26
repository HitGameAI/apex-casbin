package enforcer

import (
	"slices"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNamedPolicyReadReturnsSnapshot(t *testing.T) {
	e := newTestEnforcer(t, aclModelPath, aclPolicyPath)
	t.Cleanup(e.Close)

	for _, getter := range []struct {
		name string
		read func() [][]string
	}{
		{"named", func() [][]string { return e.GetNamedPolicy("p") }},
		{"filtered-named", func() [][]string { return e.GetFilteredNamedPolicy("p", 0, "alice") }},
		{"default", e.GetPolicy},
		{"default-filtered", func() [][]string { return e.GetFilteredPolicy(0, "alice") }},
	} {
		t.Run(getter.name, func(t *testing.T) {
			rows := getter.read()
			require.NotEmpty(t, rows)
			original := rows[0][0]
			rows[0][0] = "caller-owned"
			fresh := getter.read()
			require.NotEmpty(t, fresh)
			require.Equal(t, original, fresh[0][0])
		})
	}
}

func TestNamedPolicyReadDuringReload(t *testing.T) {
	e := newTestEnforcer(t, aclModelPath, aclPolicyPath)
	t.Cleanup(e.Close)
	snapshot := func(rows [][]string) [][]string {
		result := slices.Clone(rows)
		for i, row := range rows {
			result[i] = slices.Clone(row)
		}
		return result
	}

	wantAll := snapshot(e.GetNamedPolicy("p"))
	wantAlice := snapshot(e.GetFilteredNamedPolicy("p", 0, "alice"))
	require.NotEmpty(t, wantAll)
	require.NotEmpty(t, wantAlice)

	start := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		<-start
		for range 100 {
			if err := e.reloadPolicyForRemoteChange(); err != nil {
				done <- err
				return
			}
		}
		done <- nil
	}()
	defer func() { require.NoError(t, <-done) }()
	close(start)
	for range 100 {
		require.Equal(t, wantAll, e.GetNamedPolicy("p"))
		require.Equal(t, wantAlice, e.GetFilteredNamedPolicy("p", 0, "alice"))
		require.Equal(t, wantAll, e.GetPolicy())
		require.Equal(t, wantAlice, e.GetFilteredPolicy(0, "alice"))
		require.True(t, e.HasNamedPolicy("p", wantAlice[0]...))
	}
}
