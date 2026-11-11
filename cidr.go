package cdncheck

import (
	"math/big"
	"net/netip"
	"sort"

	"github.com/gaissmai/bart"
)

// CIDRBlock is a homogeneous CIDR partition of an input prefix.
//
// Every address inside Prefix has the same classification
// (Matched/ItemType/Provider). Blocks produced by CheckCIDR are maximal:
// adjacent blocks with an identical classification are merged into the
// smallest possible set of aligned CIDRs.
type CIDRBlock struct {
	// Input is the original (unmodified) user input this block was derived from.
	Input string `json:"input"`
	// Prefix is the canonical, masked CIDR block.
	Prefix netip.Prefix `json:"prefix"`
	// Matched reports whether the block belongs to a known CDN/WAF/Cloud range.
	Matched bool `json:"matched"`
	// ItemType is the classification category: cdn, waf or cloud.
	// It is empty for unmatched blocks.
	ItemType string `json:"item_type,omitempty"`
	// Provider is the identified provider name. It is empty for unmatched blocks.
	Provider string `json:"provider,omitempty"`
	// AddressCount is the exact number of addresses contained in Prefix.
	// It uses arbitrary precision so that IPv6 prefixes (up to 2^128) are
	// expressed exactly and never overflow.
	AddressCount *big.Int `json:"address_count"`
}

// label is the effective classification of an address. The zero value means
// the address is unmatched.
type label struct {
	itemType string
	provider string
}

// blockLabel returns the classification label of a result block.
func blockLabel(b CIDRBlock) label {
	return label{itemType: b.ItemType, provider: b.Provider}
}

// lookupAddr returns the provider whose ranges contain addr. Provider names
// are iterated in a deterministic (sorted) order so aggregate results are
// stable across runs.
func (p *providerScraper) lookupAddr(addr netip.Addr) (string, bool) {
	for _, provider := range p.sortedProviders() {
		if _, ok := p.rangers[provider].Lookup(addr); ok {
			return provider, true
		}
	}
	return "", false
}

// forEachSubnet calls fn for every known prefix strictly contained in pfx
// across all provider tables of the scraper.
func (p *providerScraper) forEachSubnet(pfx netip.Prefix, fn func(netip.Prefix)) {
	for _, provider := range p.sortedProviders() {
		for subnet := range p.rangers[provider].Subnets(pfx) {
			// Subnets includes an exact-length match; only strict subnets
			// represent classification boundaries inside the block.
			if subnet.Bits() > pfx.Bits() {
				fn(subnet.Masked())
			}
		}
	}
}

// supernetProvider returns the owner of a table prefix that covers pfx
// (bits <= pfx.Bits()). Prefixes strictly contained in pfx are ignored, so
// the result describes the classification surrounding the block rather than
// boundaries inside it.
func (p *providerScraper) supernetProvider(pfx netip.Prefix) (string, bool) {
	for _, provider := range p.sortedProviders() {
		for range p.rangers[provider].Supernets(pfx) {
			return provider, true
		}
	}
	return "", false
}

func (p *providerScraper) sortedProviders() []string {
	providers := make([]string, 0, len(p.rangers))
	for provider := range p.rangers {
		providers = append(providers, provider)
	}
	sort.Strings(providers)
	return providers
}

// classifyAddr resolves the effective label of an address using the same
// precedence as Client.Check: cdn first, then waf, then cloud.
func (c *Client) classifyAddr(addr netip.Addr) label {
	if provider, ok := c.cdn.lookupAddr(addr); ok {
		return label{itemType: "cdn", provider: provider}
	}
	if provider, ok := c.waf.lookupAddr(addr); ok {
		return label{itemType: "waf", provider: provider}
	}
	if provider, ok := c.cloud.lookupAddr(addr); ok {
		return label{itemType: "cloud", provider: provider}
	}
	return label{}
}

// surroundingLabel resolves the classification of the address space in pfx
// that is not covered by prefixes strictly contained in pfx. It only
// considers covering prefixes (bits <= pfx.Bits()), applying the same
// cdn/waf/cloud precedence as Client.Check.
func (c *Client) surroundingLabel(pfx netip.Prefix) label {
	if provider, ok := c.cdn.supernetProvider(pfx); ok {
		return label{itemType: "cdn", provider: provider}
	}
	if provider, ok := c.waf.supernetProvider(pfx); ok {
		return label{itemType: "waf", provider: provider}
	}
	if provider, ok := c.cloud.supernetProvider(pfx); ok {
		return label{itemType: "cloud", provider: provider}
	}
	return label{}
}

// CheckCIDR classifies an IP or CIDR input without enumerating its addresses.
//
// The input prefix is partitioned into the minimal set of maximal, aligned
// CIDR blocks whose addresses share one classification (known provider/category
// or unmatched). Unmatched address space is preserved as regular blocks, so
// the union of the returned blocks always equals the input prefix exactly.
//
// Address counts are computed with arbitrary precision, making the method
// safe for very large IPv6 prefixes (including ::/0) that can never be
// expanded address by address.
func (c *Client) CheckCIDR(input string) ([]CIDRBlock, error) {
	pfx, err := parseInputPrefix(input)
	if err != nil {
		return nil, err
	}
	pfx = pfx.Masked()

	// Collect every known prefix strictly inside the input once. The local
	// table only records the presence of classification boundaries; effective
	// labels are always resolved through classifyAddr to stay consistent with
	// Client.Check.
	boundaries := new(bart.Table[struct{}])
	for _, scraper := range []*providerScraper{c.cdn, c.waf, c.cloud} {
		scraper.forEachSubnet(pfx, func(subnet netip.Prefix) {
			boundaries.Insert(subnet, struct{}{})
		})
	}

	blocks := make([]CIDRBlock, 0)
	var recurse func(block netip.Prefix, surrounding label)
	recurse = func(block netip.Prefix, surrounding label) {
		uniform := true
		for subnet := range boundaries.Subnets(block) {
			if subnet.Bits() == block.Bits() {
				continue
			}
			if c.classifyAddr(subnet.Addr()) != surrounding {
				uniform = false
				break
			}
		}
		if uniform {
			blocks = append(blocks, CIDRBlock{
				Input:        input,
				Prefix:       block,
				Matched:      surrounding.itemType != "",
				ItemType:     surrounding.itemType,
				Provider:     surrounding.provider,
				AddressCount: prefixAddressCount(block),
			})
			return
		}
		lower, upper := splitPrefix(block)
		recurse(lower, c.childLabel(boundaries, lower, surrounding))
		recurse(upper, c.childLabel(boundaries, upper, surrounding))
	}

	recurse(pfx, c.surroundingLabel(pfx))
	return coalesceBlocks(input, blocks), nil
}

// coalesceBlocks merges adjacent aligned sibling blocks sharing the same
// classification into their parent CIDR until no further merge is possible.
// The result is the minimal set of maximal homogeneous CIDRs.
func coalesceBlocks(input string, blocks []CIDRBlock) []CIDRBlock {
	if len(blocks) < 2 {
		return blocks
	}
	merged := make([]CIDRBlock, 0, len(blocks))
	for _, block := range blocks {
		merged = append(merged, block)
		for len(merged) >= 2 {
			left, right := merged[len(merged)-2], merged[len(merged)-1]
			parent, ok := siblingParent(left.Prefix, right.Prefix)
			if !ok || blockLabel(left) != blockLabel(right) {
				break
			}
			merged = merged[:len(merged)-2]
			merged = append(merged, CIDRBlock{
				Input:        input,
				Prefix:       parent,
				Matched:      right.Matched,
				ItemType:     right.ItemType,
				Provider:     right.Provider,
				AddressCount: prefixAddressCount(parent),
			})
		}
	}
	return merged
}

// siblingParent returns the common parent CIDR if a and b are aligned
// lower/upper sibling prefixes of equal length.
func siblingParent(a, b netip.Prefix) (netip.Prefix, bool) {
	a, b = a.Masked(), b.Masked()
	if a.Bits() != b.Bits() || a.Bits() == 0 || a.Addr().Is4() != b.Addr().Is4() {
		return netip.Prefix{}, false
	}
	parent := netip.PrefixFrom(a.Addr(), a.Bits()-1).Masked()
	lower, upper := splitPrefix(parent)
	if lower == a && upper == b {
		return parent, true
	}
	return netip.Prefix{}, false
}

// childLabel determines the surrounding label of a split child. A child that
// is itself a known prefix takes the label of prefixes covering it (ignoring
// its own strict subnets); any other child inherits the parent surrounding
// label, which keeps deep, network-aligned prefixes from leaking into the
// space around them.
func (c *Client) childLabel(boundaries *bart.Table[struct{}], child netip.Prefix, parent label) label {
	if _, ok := boundaries.Get(child); ok {
		return c.surroundingLabel(child)
	}
	return parent
}

// parseInputPrefix accepts a single IP address or a CIDR string. A bare IP is
// treated as a host prefix (/32 or /128).
func parseInputPrefix(input string) (netip.Prefix, error) {
	if pfx, err := netip.ParsePrefix(input); err == nil {
		return pfx, nil
	}
	addr, err := netip.ParseAddr(input)
	if err != nil {
		return netip.Prefix{}, err
	}
	return netip.PrefixFrom(addr, addr.BitLen()), nil
}

// splitPrefix splits a prefix into its two aligned (bits+1) halves.
func splitPrefix(pfx netip.Prefix) (lower, upper netip.Prefix) {
	pfx = pfx.Masked()
	bits := pfx.Bits()

	raw := pfx.Addr().AsSlice()
	upperRaw := append(make([]byte, 0, len(raw)), raw...)
	// set the first bit after the prefix (MSB-first numbering inside the byte)
	upperRaw[bits/8] |= 1 << (7 - bits%8)

	upperAddr, ok := netip.AddrFromSlice(upperRaw)
	if !ok {
		// unreachable: the slice length matches the address family
		return netip.Prefix{}, netip.Prefix{}
	}
	lower = netip.PrefixFrom(pfx.Addr(), bits+1)
	upper = netip.PrefixFrom(upperAddr.Unmap(), bits+1)
	return lower, upper
}

// prefixAddressCount returns the exact number of addresses in pfx as a
// big.Int, supporting IPv6 prefixes up to 2^128.
func prefixAddressCount(pfx netip.Prefix) *big.Int {
	hostBits := uint(pfx.Addr().BitLen() - pfx.Bits())
	return new(big.Int).Lsh(big.NewInt(1), hostBits)
}
