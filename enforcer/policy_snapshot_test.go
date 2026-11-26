package enforcer

import (
	"context"
	"slices"
	"testing"
	"time"

	"github.com/HitGameAI/apex-casbin/policy"
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

func TestDomainRoleReadsDuringReload(t *testing.T) {
	e := newTestEnforcer(t, rbacDomainModelPath, rbacDomainPolicyPath)
	require.NoError(t, e.AddGroupingPolicy("admin", "reader", "tenant1"))
	require.NoError(t, e.AddGroupingPolicy("charlie", "role", "tenant1"))
	require.NoError(t, e.AddGroupingPolicy("role", "reader", "tenant1"))

	type roleRead struct {
		name string
		read func() []string
		want []string
	}
	reads := []roleRead{
		{"roles for user", func() []string { return e.GetRolesForUser("alice", "tenant1") }, []string{"admin"}},
		{"roles in first tenant", func() []string { return e.GetRolesForUserInDomain("alice", "tenant1") }, []string{"admin"}},
		{"roles in second tenant", func() []string { return e.GetRolesForUserInDomain("alice", "tenant2") }, []string{"viewer"}},
		{"users for role", func() []string { return e.GetUsersForRole("admin", "tenant1") }, []string{"alice"}},
		{"users in domain", func() []string { return e.GetUsersForRoleInDomain("admin", "tenant1") }, []string{"alice"}},
		{"inherited roles", func() []string { return e.GetImplicitRolesForUser("alice", "tenant1") }, []string{"admin", "reader"}},
		{"all domains", e.GetAllDomains, []string{"tenant1", "tenant2"}},
		{"all users in domain", func() []string { return e.GetAllUsersByDomain("tenant1") }, []string{"charlie"}},
		{"all roles in domain", func() []string { return e.GetAllRolesByDomain("tenant1") }, []string{"reader"}},
	}
	for _, read := range reads {
		result := read.read()
		require.ElementsMatch(t, read.want, result, read.name)
		result[0] = "caller-owned"
		require.ElementsMatch(t, read.want, read.read(), read.name)
	}

	adapter := &pausedRoleReloadAdapter{
		Adapter: e.policy.GetAdapter(),
		entered: make(chan struct{}),
		resume:  make(chan struct{}),
	}
	e.policy.SetAdapter(adapter)
	reloaded := make(chan error, 1)
	go func() { reloaded <- e.reloadPolicyForRemoteChange() }()
	<-adapter.entered

	// The adapter is paused with the reload holding the write lock. This checks
	// the overlap directly, including methods whose result might otherwise come
	// from an already warm role cache.
	type readResult struct {
		name string
		got  []string
		want []string
	}
	results := make(chan readResult, len(reads))
	for _, read := range reads {
		go func() { results <- readResult{read.name, read.read(), read.want} }()
	}
	membership := make(chan bool, 1)
	go func() { membership <- e.HasRoleForUser("alice", "reader", "tenant1") }()

	remaining := len(reads)
	membershipRead := false
	select {
	case result := <-results:
		t.Errorf("%s completed with the reload holding the write lock", result.name)
		remaining--
	case <-membership:
		t.Error("role membership completed with the reload holding the write lock")
		membershipRead = true
	case <-time.After(40 * time.Millisecond):
	}
	close(adapter.resume)
	require.NoError(t, <-reloaded)
	for range remaining {
		result := <-results
		require.ElementsMatch(t, result.want, result.got, result.name)
	}
	if !membershipRead {
		require.True(t, <-membership)
	}
	require.False(t, e.HasRoleForUser("alice", "reader", "tenant2"))
}

type pausedRoleReloadAdapter struct {
	policy.Adapter
	entered chan struct{}
	resume  chan struct{}
}

func (a *pausedRoleReloadAdapter) LoadPolicy() ([]string, error) {
	close(a.entered)
	<-a.resume
	return a.Adapter.LoadPolicy()
}
