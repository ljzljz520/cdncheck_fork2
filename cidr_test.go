package cdncheck

import (
	"math/big"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// prefixLastAddr returns the last address covered by pfx.
func prefixLastAddr(pfx netip.Prefix) netip.Addr {
	pfx = pfx.Masked()
	raw := pfx.Addr().AsSlice()
	first := new(big.Int).SetBytes(raw)
	last := new(big.Int).Add(first, new(big.Int).Sub(prefixAddressCount(pfx), big.NewInt(1)))
	lastBytes := last.Bytes()
	fixed := make([]byte, len(raw))
	copy(fixed[len(raw)-len(lastBytes):], lastBytes)
	addr, _ := netip.AddrFromSlice(fixed)
	return addr.Unmap()
}

// requireContiguousCoverage asserts that the blocks partition the input
// prefix exactly: canonical, sorted, pairwise disjoint and gap-free, and
// that the summed address count equals the input prefix count.
func requireContiguousCoverage(t *testing.T, input string, blocks []CIDRBlock) netip.Prefix {
	t.Helper()
	require.NotEmpty(t, blocks)

	root, err := netip.ParsePrefix(input)
	require.NoError(t, err)
	root = root.Masked()

	cursor := root.Addr()
	total := new(big.Int)
	for _, b := range blocks {
		require.Equal(t, input, b.Input, "original input must be preserved")
		require.True(t, b.Prefix.IsValid())
		require.Equal(t, b.Prefix, b.Prefix.Masked(), "block prefix must be canonical")
		require.True(t, b.Prefix.Addr().Is4() == root.Addr().Is4())
		require.True(t, root.Overlaps(b.Prefix))
		// sorted and gap-free
		require.Equal(t, cursor, b.Prefix.Addr(), "blocks must be contiguous")
		cursor = prefixLastAddr(b.Prefix).Next()
		total.Add(total, b.AddressCount)
	}
	// cursor now sits one past the last address of the input prefix
	require.Equal(t, prefixLastAddr(root).Next(), cursor)
	require.Equal(t, 0, prefixAddressCount(root).Cmp(total), "address counts must add up to the input size")
	return root
}

// requireMaximalPartition asserts no two sibling blocks carry the same
// label: such siblings would have been emitted as their merged parent.
func requireMaximalPartition(t *testing.T, blocks []CIDRBlock) {
	t.Helper()
	for i := 0; i+1 < len(blocks); i++ {
		a, b := blocks[i].Prefix, blocks[i+1].Prefix
		if a.Bits() != b.Bits() {
			continue
		}
		parentA := netip.PrefixFrom(a.Masked().Addr(), a.Bits()-1).Masked()
		parentB := netip.PrefixFrom(b.Masked().Addr(), b.Bits()-1).Masked()
		if parentA == parentB {
			require.NotEqual(t, blockLabel(blocks[i]), blockLabel(blocks[i+1]),
				"sibling blocks with the same label must be merged: %s %s", a, b)
		}
	}
}

// requirePerIPCrossCheck enumerates every address of a (small) prefix and
// confirms that the aggregate partition agrees with the per-IP Check rule
// for each address, including block boundary addresses.
func requirePerIPCrossCheck(t *testing.T, client *Client, input string) []CIDRBlock {
	t.Helper()
	blocks, err := client.CheckCIDR(input)
	require.NoError(t, err)
	root := requireContiguousCoverage(t, input, blocks)
	requireMaximalPartition(t, blocks)

	hostBits := root.Addr().BitLen() - root.Bits()
	require.LessOrEqual(t, hostBits, 10, "cross-check helper only enumerates small prefixes")
	count := 1 << hostBits

	findBlock := func(addr netip.Addr) int {
		for i, b := range blocks {
			if b.Prefix.Contains(addr) {
				return i
			}
		}
		return -1
	}

	addr := root.Addr()
	for i := 0; i < count; i++ {
		matched, provider, itemType, err := client.Check(net.ParseIP(addr.String()))
		require.NoError(t, err)
		idx := findBlock(addr)
		require.GreaterOrEqual(t, idx, 0, "address %s not covered by any block", addr)
		block := blocks[idx]
		require.Equal(t, matched, block.Matched, "matched mismatch at %s", addr)
		if matched {
			require.Equal(t, itemType, block.ItemType, "item type mismatch at %s", addr)
			require.Equal(t, provider, block.Provider, "provider mismatch at %s", addr)
		} else {
			require.Empty(t, block.ItemType)
			require.Empty(t, block.Provider)
		}
		addr = addr.Next()
	}

	// boundary addresses: first and last address of every block follow the rule
	for _, b := range blocks {
		for _, boundary := range []netip.Addr{b.Prefix.Addr(), prefixLastAddr(b.Prefix)} {
			matched, provider, itemType, err := client.Check(net.ParseIP(boundary.String()))
			require.NoError(t, err)
			require.Equal(t, matched, b.Matched)
			if matched {
				require.Equal(t, itemType, b.ItemType)
				require.Equal(t, provider, b.Provider)
			}
		}
	}
	return blocks
}

func TestCheckCIDRIPv4PerIPCrossCheck(t *testing.T) {
	client := New()
	// 38.142.1.0/24 contains two cloudflare WAF islands: .64/29 and .192/29.
	blocks := requirePerIPCrossCheck(t, client, "38.142.1.0/24")

	var matchedCount int
	for _, b := range blocks {
		if b.Matched {
			matchedCount++
			require.Equal(t, "waf", b.ItemType)
			require.Equal(t, "cloudflare", b.Provider)
		}
	}
	require.Equal(t, 2, matchedCount, "the two /29 islands must each form one block")

	byPrefix := map[string]CIDRBlock{}
	for _, b := range blocks {
		byPrefix[b.Prefix.String()] = b
	}
	require.Contains(t, byPrefix, "38.142.1.64/29")
	require.Contains(t, byPrefix, "38.142.1.192/29")
	require.Equal(t, "8", byPrefix["38.142.1.64/29"].AddressCount.String())
}

func TestCheckCIDRIPv6PerIPCrossCheck(t *testing.T) {
	client := New()

	// /120 fully inside the cloudflare WAF 2001:868:100:5300::/56 range.
	inside := requirePerIPCrossCheck(t, client, "2001:868:100:5300::/120")
	require.Len(t, inside, 1)
	require.True(t, inside[0].Matched)
	require.Equal(t, "waf", inside[0].ItemType)
	require.Equal(t, "cloudflare", inside[0].Provider)
	require.Equal(t, "256", inside[0].AddressCount.String())

	// /120 just past the /56 boundary must be fully unmatched.
	outside := requirePerIPCrossCheck(t, client, "2001:868:100:5400::/120")
	require.Len(t, outside, 1)
	require.False(t, outside[0].Matched)
	require.Equal(t, "256", outside[0].AddressCount.String())
}

func TestCheckCIDRMaximalMerge(t *testing.T) {
	client := New()
	// The whole 141.101.64.0/20 is cloudflare WAF address space; it must be
	// returned as a single merged block instead of the source sub-prefixes.
	blocks, err := client.CheckCIDR("141.101.64.0/20")
	require.NoError(t, err)
	require.Len(t, blocks, 1)
	require.True(t, blocks[0].Matched)
	require.Equal(t, "waf", blocks[0].ItemType)
	require.Equal(t, "cloudflare", blocks[0].Provider)
	require.Equal(t, "4096", blocks[0].AddressCount.String())
}

func TestCheckCIDRLargePrefixesNoEnumeration(t *testing.T) {
	client := New()

	cases := []struct {
		input       string
		wantCount   string
		singleBlock bool
		matched     bool
	}{
		// Entire IPv6 space: 2^128 addresses, still processable.
		{"::/0", new(big.Int).Lsh(big.NewInt(1), 128).String(), false, false},
		// Fully unmatched documentation range collapses to one block.
		{"2001:db8::/32", new(big.Int).Lsh(big.NewInt(1), 96).String(), true, false},
		// A known /56 keeps its exact 2^72 count.
		{"2001:868:100:5300::/56", new(big.Int).Lsh(big.NewInt(1), 72).String(), true, true},
		// Entire IPv4 space: 2^32 addresses.
		{"0.0.0.0/0", new(big.Int).Lsh(big.NewInt(1), 32).String(), false, false},
	}

	for _, tc := range cases {
		start := time.Now()
		blocks, err := client.CheckCIDR(tc.input)
		require.NoError(t, err)
		// Enumerating any of these prefixes address by address could never
		// finish; the aggregate partition must return promptly.
		require.Less(t, time.Since(start), 30*time.Second, tc.input)

		requireContiguousCoverage(t, tc.input, blocks)
		requireMaximalPartition(t, blocks)

		total := new(big.Int)
		hasMatched := false
		for _, b := range blocks {
			total.Add(total, b.AddressCount)
			if b.Matched {
				hasMatched = true
			}
		}
		require.Equal(t, tc.wantCount, total.String(), "exact address count for %s", tc.input)
		if tc.singleBlock {
			require.Len(t, blocks, 1, tc.input)
			require.Equal(t, tc.matched, blocks[0].Matched, tc.input)
		}
		if tc.matched {
			require.True(t, hasMatched, tc.input)
		}
	}
}

func TestCheckCIDRComplementCompleteness(t *testing.T) {
	client := New()

	// On small prefixes the complement must equal, address by address, the
	// set of IPs that Check reports as unmatched.
	smallInputs := []string{"38.142.1.0/24", "2001:868:100:5300::/120", "2001:868:100:5400::/120"}
	for _, input := range smallInputs {
		blocks, err := client.CheckCIDR(input)
		require.NoError(t, err)
		root, _ := netip.ParsePrefix(input)
		root = root.Masked()

		matchedSum, complementSum := new(big.Int), new(big.Int)
		addr := root.Addr()
		count := 1 << (root.Addr().BitLen() - root.Bits())
		for i := 0; i < count; i++ {
			matched, _, _, err := client.Check(net.ParseIP(addr.String()))
			require.NoError(t, err)

			var block *CIDRBlock
			for j := range blocks {
				if blocks[j].Prefix.Contains(addr) {
					block = &blocks[j]
					break
				}
			}
			require.NotNil(t, block)
			require.Equal(t, matched, block.Matched)
			addr = addr.Next()
		}
		for i := range blocks {
			if blocks[i].Matched {
				matchedSum.Add(matchedSum, blocks[i].AddressCount)
			} else {
				complementSum.Add(complementSum, blocks[i].AddressCount)
			}
		}
		total := new(big.Int).Add(matchedSum, complementSum)
		require.Equal(t, 0, prefixAddressCount(root).Cmp(total))
	}

	// On a huge prefix the complement stays exact through big.Int arithmetic.
	blocks, err := client.CheckCIDR("::/0")
	require.NoError(t, err)
	matchedSum, complementSum := new(big.Int), new(big.Int)
	for _, b := range blocks {
		if b.Matched {
			matchedSum.Add(matchedSum, b.AddressCount)
		} else {
			require.Empty(t, b.ItemType)
			complementSum.Add(complementSum, b.AddressCount)
		}
	}
	require.Equal(t, new(big.Int).Lsh(big.NewInt(1), 128),
		new(big.Int).Add(matchedSum, complementSum))
	require.True(t, matchedSum.Sign() > 0)
	require.True(t, complementSum.Sign() > 0)
}

func TestCheckCIDRCanonicalizationAndBareIPs(t *testing.T) {
	client := New()

	// Host bits are normalized while the raw input is preserved.
	blocks, err := client.CheckCIDR("38.142.1.65/29")
	require.NoError(t, err)
	require.Len(t, blocks, 1)
	require.Equal(t, "38.142.1.65/29", blocks[0].Input)
	require.Equal(t, "38.142.1.64/29", blocks[0].Prefix.String())
	require.True(t, blocks[0].Matched)

	// Bare IPv4 address becomes a /32.
	blocks, err = client.CheckCIDR("38.142.1.65")
	require.NoError(t, err)
	require.Len(t, blocks, 1)
	require.Equal(t, "38.142.1.65/32", blocks[0].Prefix.String())
	require.Equal(t, "1", blocks[0].AddressCount.String())
	require.True(t, blocks[0].Matched)

	// Bare IPv6 address becomes a /128.
	blocks, err = client.CheckCIDR("2400:cb00::1")
	require.NoError(t, err)
	require.Len(t, blocks, 1)
	require.Equal(t, "2400:cb00::1/128", blocks[0].Prefix.String())
	require.Equal(t, "1", blocks[0].AddressCount.String())
	require.True(t, blocks[0].Matched)
	require.Equal(t, "waf", blocks[0].ItemType)
	require.Equal(t, "cloudflare", blocks[0].Provider)

	// Unmatched bare address stays unmatched but is still returned.
	blocks, err = client.CheckCIDR("192.0.2.1")
	require.NoError(t, err)
	require.Len(t, blocks, 1)
	require.False(t, blocks[0].Matched)

	_, err = client.CheckCIDR("not-an-ip-or-cidr")
	require.Error(t, err)
}

func TestSplitPrefixAndAddressCount(t *testing.T) {
	lo, hi := splitPrefix(netip.MustParsePrefix("10.0.0.0/24"))
	require.Equal(t, "10.0.0.0/25", lo.String())
	require.Equal(t, "10.0.0.128/25", hi.String())

	lo, hi = splitPrefix(netip.MustParsePrefix("2001:db8::/32"))
	require.Equal(t, "2001:db8::/33", lo.String())
	require.Equal(t, "2001:db8:8000::/33", hi.String())

	lo, hi = splitPrefix(netip.MustParsePrefix("::/0"))
	require.Equal(t, "::/1", lo.String())
	require.Equal(t, "8000::/1", hi.String())

	require.Equal(t, "1", prefixAddressCount(netip.MustParsePrefix("1.2.3.4/32")).String())
	require.Equal(t, "1", prefixAddressCount(netip.MustParsePrefix("::1/128")).String())
	require.Equal(t, "2", prefixAddressCount(netip.MustParsePrefix("::/127")).String())
	require.Equal(t, new(big.Int).Lsh(big.NewInt(1), 128).String(),
		prefixAddressCount(netip.MustParsePrefix("::/0")).String())
}
