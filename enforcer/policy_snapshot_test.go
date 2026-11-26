package enforcer

import (
	"context"
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

func TestGroupingAndPermissionReadsReturnSnapshots(t *testing.T) {
	e := newTestEnforcer(t, rbacModelPath, rbacPolicyPath)
	t.Cleanup(e.Close)

	for _, getter := range []struct {
		name string
		read func(*Enforcer) [][]string
	}{
		{"grouping", (*Enforcer).GetGroupingPolicy},
		{"filtered-grouping", func(e *Enforcer) [][]string { return e.GetFilteredGroupingPolicy(0, "alice") }},
		{"named-grouping", func(e *Enforcer) [][]string { return e.GetNamedGroupingPolicy("g") }},
		{"filtered-named-grouping", func(e *Enforcer) [][]string { return e.GetFilteredNamedGroupingPolicy("g", 0, "alice") }},
		{"direct-permissions", func(e *Enforcer) [][]string { return e.GetPermissionsForUser("alice") }},
		{"implicit-permissions", func(e *Enforcer) [][]string { return e.GetImplicitPermissionsForUser("alice") }},
	} {
		t.Run(getter.name, func(t *testing.T) {
			// A failing subtest must not corrupt the fixture for another getter.
			enforcer := newTestEnforcer(t, rbacModelPath, rbacPolicyPath)
			t.Cleanup(enforcer.Close)
			got := getter.read(enforcer)
			require.NotEmpty(t, got)
			want := clonePolicyRows(got)
			got[0][0] = "caller-owned"
			got[0] = nil
			require.ElementsMatch(t, want, getter.read(enforcer))
		})
	}

	users := e.GetAllUsers()
	require.Contains(t, users, "alice")
	users[0] = "caller-owned"
	require.NotContains(t, e.GetAllUsers(), "caller-owned")

	implicitUsers := e.GetImplicitUsersForPermission("data2", "read")
	require.Contains(t, implicitUsers, "alice")
	implicitUsers[0] = "caller-owned"
	require.NotContains(t, e.GetImplicitUsersForPermission("data2", "read"), "caller-owned")
}

func TestGroupingAndPermissionReadsDuringReload(t *testing.T) {
	e := newTestEnforcer(t, rbacModelPath, rbacPolicyPath)
	t.Cleanup(e.Close)

	grouping := clonePolicyRows(e.GetGroupingPolicy())
	filtered := clonePolicyRows(e.GetFilteredGroupingPolicy(0, "alice"))
	direct := clonePolicyRows(e.GetPermissionsForUser("alice"))
	implicit := clonePolicyRows(e.GetImplicitPermissionsForUser("alice"))
	users := slices.Clone(e.GetAllUsers())
	implicitUsers := slices.Clone(e.GetImplicitUsersForPermission("data2", "read"))
	require.NotEmpty(t, grouping)
	require.NotEmpty(t, filtered)
	require.NotEmpty(t, direct)
	require.NotEmpty(t, implicit)
	require.NotEmpty(t, users)
	require.NotEmpty(t, implicitUsers)

	listGetters := []func() []string{
		e.GetAllSubjects,
		e.GetAllObjects,
		e.GetAllActions,
		e.GetAllRoles,
		func() []string { return e.GetAllNamedSubjects("p") },
		func() []string { return e.GetAllNamedObjects("p") },
		func() []string { return e.GetAllNamedActions("p") },
		func() []string { return e.GetAllNamedRoles("g") },
	}
	lists := make([][]string, len(listGetters))
	for i, read := range listGetters {
		lists[i] = slices.Clone(read())
		require.NotEmpty(t, lists[i])
	}

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
		require.Equal(t, grouping, e.GetGroupingPolicy())
		require.Equal(t, grouping, e.GetNamedGroupingPolicy("g"))
		require.Equal(t, filtered, e.GetFilteredGroupingPolicy(0, "alice"))
		require.Equal(t, filtered, e.GetFilteredNamedGroupingPolicy("g", 0, "alice"))
		require.Equal(t, direct, e.GetPermissionsForUser("alice"))
		require.ElementsMatch(t, implicit, e.GetImplicitPermissionsForUser("alice"))
		require.ElementsMatch(t, users, e.GetAllUsers())
		require.ElementsMatch(t, implicitUsers, e.GetImplicitUsersForPermission("data2", "read"))
		require.True(t, e.HasGroupingPolicy(filtered[0]...))
		require.True(t, e.HasNamedGroupingPolicy("g", filtered[0]...))
		require.True(t, e.HasPolicy(direct[0]...))
		require.True(t, e.HasPermissionForUser("alice", direct[0][1:]...))

		for i, read := range listGetters {
			require.ElementsMatch(t, lists[i], read())
		}
	}
}

func TestExecuteInTransactionReadsThroughPolicyManager(t *testing.T) {
	e := newTestEnforcer(t, rbacModelPath, rbacPolicyPath)
	t.Cleanup(e.Close)
	want := e.GetFilteredGroupingPolicy(0, "alice")
	require.NotEmpty(t, want)

	var policies [][]string
	require.NoError(t, e.ExecuteInTransaction(context.Background(), func() error {
		// The callback already owns the write lock. Use the policy manager inside
		// it and detach the result before releasing that lock.
		policies = clonePolicyRows(e.GetPolicyManager().GetFilteredPolicy("g", 0, "alice"))
		return nil
	}))
	require.Equal(t, want, policies)
	policies[0][0] = "caller-owned"
	require.Equal(t, want, e.GetFilteredGroupingPolicy(0, "alice"))
}

func TestDomainPermissionReadReturnsSnapshot(t *testing.T) {
	e := newTestEnforcer(t, rbacDomainModelPath, rbacDomainPolicyPath)
	t.Cleanup(e.Close)

	policies := e.GetPermissionsForUserInDomain("alice", "tenant1")
	require.NotEmpty(t, policies)
	want := clonePolicyRows(policies)
	policies[0][0] = "caller-owned"
	require.Equal(t, want, e.GetPermissionsForUserInDomain("alice", "tenant1"))
}
