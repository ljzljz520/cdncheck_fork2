package runner

import (
	"math/big"
	"net/netip"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRunWithThreadsReturnsEveryInput(t *testing.T) {
	inputs := []string{
		"192.0.2.1",
		"192.0.2.2",
		"192.0.2.3",
		"192.0.2.4",
		"198.51.100.1",
		"198.51.100.2",
		"203.0.113.1",
		"203.0.113.2",
	}

	var mu sync.Mutex
	got := map[string]int{}
	runner := NewRunner(&Options{
		Inputs:  inputs,
		Threads: 4,
		Exclude: true,
		OnResult: func(result Output) {
			mu.Lock()
			got[result.Input]++
			mu.Unlock()
		},
	})

	require.NoError(t, runner.Run())
	require.Len(t, got, len(inputs))
	for _, input := range inputs {
		require.Equal(t, 1, got[input])
	}
}

func runAndCollect(t *testing.T, opts *Options) []Output {
	t.Helper()
	var mu sync.Mutex
	collected := make([]Output, 0)
	opts.OnResult = func(result Output) {
		mu.Lock()
		collected = append(collected, result)
		mu.Unlock()
	}
	runner := NewRunner(opts)
	require.NoError(t, runner.Run())
	return collected
}

// TestRunnerAggregateCIDR verifies aggregate mode emits homogeneous CIDR
// blocks, preserves the original input and reports exact address counts.
func TestRunnerAggregateCIDR(t *testing.T) {
	const input = "38.142.1.0/24"
	results := runAndCollect(t, &Options{
		Inputs:        []string{input},
		Threads:       4,
		AggregateCidr: true,
	})

	require.NotEmpty(t, results)
	total := new(big.Int)
	seenPrefixes := map[string]bool{}
	for _, r := range results {
		require.True(t, r.aggregate)
		require.Equal(t, input, r.Input, "original input must be preserved")
		require.NotEmpty(t, r.Prefix)
		require.False(t, seenPrefixes[r.Prefix], "duplicate block %s", r.Prefix)
		seenPrefixes[r.Prefix] = true

		pfx, err := netip.ParsePrefix(r.Prefix)
		require.NoError(t, err)
		count, ok := new(big.Int).SetString(r.AddressCount, 10)
		require.True(t, ok)
		require.Equal(t, 0, count.Cmp(new(big.Int).Lsh(big.NewInt(1), uint(pfx.Addr().BitLen()-pfx.Bits()))))
		total.Add(total, count)

		require.True(t, r.Waf)
		require.Equal(t, "cloudflare", r.WafName)
	}
	// only matched blocks are emitted without --exclude
	require.Equal(t, "16", total.String(), "two cloudflare /29 islands = 16 addresses")
	require.Contains(t, seenPrefixes, "38.142.1.64/29")
	require.Contains(t, seenPrefixes, "38.142.1.192/29")
}

// TestRunnerAggregateCIDRExcludeComplement verifies exclude mode emits the
// complement of the identified space and that it covers the input exactly.
func TestRunnerAggregateCIDRExcludeComplement(t *testing.T) {
	const input = "38.142.1.0/24"
	results := runAndCollect(t, &Options{
		Inputs:        []string{input},
		Threads:       4,
		AggregateCidr: true,
		Exclude:       true,
	})

	require.NotEmpty(t, results)
	total := new(big.Int)
	for _, r := range results {
		require.True(t, r.aggregate)
		require.Equal(t, input, r.Input)
		require.False(t, r.Cdn || r.Cloud || r.Waf, "complement blocks must be unmatched")
		count, ok := new(big.Int).SetString(r.AddressCount, 10)
		require.True(t, ok)
		total.Add(total, count)
	}
	// 256 total addresses minus the 16 identified cloudflare addresses
	require.Equal(t, "240", total.String())
}

// TestRunnerAggregateCIDRFilters wires aggregate output through the existing
// category flags and provider match/filter options.
func TestRunnerAggregateCIDRFilters(t *testing.T) {
	const input = "38.142.1.0/24"

	matched := runAndCollect(t, &Options{
		Inputs:        []string{input},
		Threads:       4,
		AggregateCidr: true,
		MatchWaf:      []string{"cloudflare"},
	})
	require.NotEmpty(t, matched)
	for _, r := range matched {
		require.True(t, r.Waf)
		require.Equal(t, "cloudflare", r.WafName)
	}

	unknownProvider := runAndCollect(t, &Options{
		Inputs:        []string{input},
		Threads:       4,
		AggregateCidr: true,
		MatchWaf:      []string{"does-not-exist"},
	})
	require.Empty(t, unknownProvider)

	filteredOut := runAndCollect(t, &Options{
		Inputs:        []string{input},
		Threads:       4,
		AggregateCidr: true,
		FilterWaf:     []string{"cloudflare"},
	})
	require.Empty(t, filteredOut)

	categoryOnly := runAndCollect(t, &Options{
		Inputs:        []string{input},
		Threads:       4,
		AggregateCidr: true,
		Waf:           true,
	})
	require.NotEmpty(t, categoryOnly)
	for _, r := range categoryOnly {
		require.True(t, r.Waf)
	}

	cdnCategory := runAndCollect(t, &Options{
		Inputs:        []string{input},
		Threads:       4,
		AggregateCidr: true,
		Cdn:           true,
	})
	require.Empty(t, cdnCategory)
}

// TestRunnerAggregateCIDRIPv6NoEnumeration ensures a large IPv6 prefix is
// processed as blocks with an exact 2^72 address count, never enumerated.
func TestRunnerAggregateCIDRIPv6NoEnumeration(t *testing.T) {
	results := runAndCollect(t, &Options{
		Inputs:        []string{"2001:868:100:5300::/56"},
		Threads:       1,
		AggregateCidr: true,
	})
	require.Len(t, results, 1)
	r := results[0]
	require.True(t, r.aggregate)
	require.Equal(t, "2001:868:100:5300::/56", r.Prefix)
	require.Equal(t, new(big.Int).Lsh(big.NewInt(1), 72).String(), r.AddressCount)
	require.True(t, r.Waf)
	require.Equal(t, "cloudflare", r.WafName)
}

// TestRunnerDefaultPerAddressModeCompatible guarantees the default path
// still enumerates CIDR inputs address by address when aggregation is off.
func TestRunnerDefaultPerAddressModeCompatible(t *testing.T) {
	const input = "38.142.1.0/24"

	// matched addresses only: the two /29 cloudflare islands
	matched := runAndCollect(t, &Options{Inputs: []string{input}, Threads: 4})
	require.Len(t, matched, 16)
	for _, r := range matched {
		require.False(t, r.aggregate)
		require.Empty(t, r.Prefix)
		require.NotContains(t, r.Input, "/")
	}

	// exclude mode enumerates every non-identified address
	excluded := runAndCollect(t, &Options{
		Inputs:  []string{input},
		Threads: 4,
		Exclude: true,
	})
	require.Len(t, excluded, 240)
	for _, r := range excluded {
		require.False(t, r.aggregate)
		require.Empty(t, r.Prefix)
	}
}
