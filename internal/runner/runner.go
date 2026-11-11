package runner

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/logrusorgru/aurora"
	"github.com/pkg/errors"
	"github.com/projectdiscovery/cdncheck"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/mapcidr"
	iputils "github.com/projectdiscovery/utils/ip"
)

type Runner struct {
	options   *Options
	cdnclient *cdncheck.Client
	aurora    *aurora.Aurora
	writer    *OutputWriter
}

func NewRunner(options *Options) *Runner {
	standardWriter := aurora.NewAurora(!options.NoColor)
	client, err := cdncheck.NewWithOpts(options.MaxRetries, options.Resolvers)
	if err != nil {
		gologger.Fatal().Msgf("failed to create cdncheck client: %v", err)
	}
	runner := &Runner{
		options:   options,
		cdnclient: client,
		aurora:    &standardWriter,
	}
	return runner
}

func (r *Runner) Run() error {
	err := r.configureOutput()
	if err != nil {
		return errors.Wrap(err, "could not configure output")
	}
	defer r.writer.Close()
	threads := r.options.Threads
	if threads <= 0 {
		threads = 1
	}
	output := make(chan Output, threads)
	wg := &sync.WaitGroup{}
	wg.Add(1)
	go r.process(output, wg)
	wg.Add(1)
	go r.waitForData(output, wg)
	wg.Wait()
	return nil
}

func (r *Runner) SetWriter(writer io.Writer) error {
	outputWriter, err := NewOutputWriter()
	if err != nil {
		return err
	}
	outputWriter.AddWriters(writer)
	r.writer = outputWriter
	return nil
}

func (r *Runner) process(output chan Output, wg *sync.WaitGroup) {
	defer wg.Done()
	defer close(output)

	threads := r.options.Threads
	if threads <= 0 {
		threads = 1
	}

	tasks := make(chan string, threads)
	var workerWg sync.WaitGroup

	for i := 0; i < threads; i++ {
		workerWg.Add(1)
		go func() {
			defer workerWg.Done()
			for item := range tasks {
				r.processInputItemSingle(item, output)
			}
		}()
	}

	sendItem := func(input string) {
		if _, ipRange, _ := net.ParseCIDR(input); ipRange != nil {
			if r.options.AggregateCidr {
				// Aggregate mode never enumerates addresses, so large IPv6
				// prefixes stay processable.
				r.processCIDRAggregate(input, output)
				return
			}
			cidrInputs, err := mapcidr.IPAddressesAsStream(input)
			if err != nil {
				if r.options.Verbose {
					gologger.Error().Msgf("Could not parse cidr %s: %s", input, err)
				}
				return
			}
			for cidr := range cidrInputs {
				tasks <- cidr
			}
		} else {
			tasks <- input
		}
	}

	for _, target := range r.options.Inputs {
		sendItem(target)
	}
	if r.options.HasStdin {
		scanner := bufio.NewScanner(os.Stdin)
		for scanner.Scan() {
			text := scanner.Text()
			if text != "" {
				sendItem(text)
			}
		}
	}

	close(tasks)
	workerWg.Wait()
}

func (r *Runner) waitForData(output chan Output, wg *sync.WaitGroup) {
	defer wg.Done()
	var cdnCount, wafCount, cloudCount int
	for receivedData := range output {
		if receivedData.Cdn {
			cdnCount++
		} else if receivedData.Waf {
			wafCount++
		} else if receivedData.Cloud {
			cloudCount++
		}

		if r.options.OnResult != nil {
			r.options.OnResult(receivedData)
		}

		switch {
		case r.options.Json:
			r.writer.WriteJSON(receivedData)
		case receivedData.aggregate && r.options.Response:
			r.writer.WriteString(receivedData.String())
		case receivedData.aggregate:
			r.writer.WriteString(receivedData.Prefix)
		case r.options.Response && !r.options.Exclude:
			r.writer.WriteString(receivedData.String())
		default:
			r.writer.WriteString(receivedData.Input)
		}
	}

	// show summary to user
	sw := *r.aurora
	if (cdnCount + wafCount + cloudCount) < 1 {
		gologger.Info().Msgf("No results found.")
		return
	}
	var builder strings.Builder
	_, _ = fmt.Fprintf(&builder, "Found result: %v", (cdnCount + cloudCount + wafCount))
	builder.WriteString(" (")
	if cdnCount > 0 {
		_, _ = fmt.Fprintf(&builder, "%s %v", sw.BrightBlue("CDN:").String(), cdnCount)
	}
	if cloudCount > 0 {
		if cdnCount > 0 {
			builder.WriteString(", ")
		}
		_, _ = fmt.Fprintf(&builder, "%s %v", sw.BrightGreen("CLOUD:").String(), cloudCount)
	}
	if wafCount > 0 {
		if cdnCount > 0 || cloudCount > 0 {
			builder.WriteString(", ")
		}
		_, _ = fmt.Fprintf(&builder, "%s %v", sw.Yellow("WAF:").String(), wafCount)
	}
	builder.WriteString(")")
	gologger.Info().Msg(builder.String())
}

func (r *Runner) configureOutput() error {
	if r.writer != nil {
		return nil
	}
	outputWriter, err := NewOutputWriter()
	if err != nil {
		return err
	}
	if r.options.OnResult != nil {
		r.writer = outputWriter
		return nil
	}
	outputWriter.AddWriters(os.Stdout)
	if r.options.Output != "" {
		outputFile, err := os.Create(r.options.Output)
		if err != nil {
			return err
		}
		outputWriter.AddWriters(outputFile)
	}
	r.writer = outputWriter
	return nil
}

func (r *Runner) processInputItemSingle(item string, output chan Output) {
	data := Output{
		aurora: r.aurora,
		Input:  item,
	}

	var matched bool
	var provider, itemType string
	var err error

	var targetIp string
	if iputils.IsIP(item) {
		matched, provider, itemType, err = r.cdnclient.Check(net.ParseIP(item))
		targetIp = item
	} else {
		matched, provider, itemType, err = r.cdnclient.CheckDomainWithFallback(item)
		dnsData, err := r.cdnclient.GetDnsData(item)

		if err == nil {
			if len(dnsData.AAAA) > 0 {
				targetIp = dnsData.AAAA[0]
			} else if len(dnsData.A) > 0 {
				targetIp = dnsData.A[0]
			}
		}
	}
	if err != nil && r.options.Verbose {
		gologger.Error().Msgf("Could not check domain cdn %s: %s", item, err)
	}

	data.itemType = itemType
	data.IP = targetIp
	data.Timestamp = time.Now()

	if r.options.Exclude {
		if !matched {
			output <- data
		}
		return
	}

	switch itemType {
	case "cdn":
		data.Cdn = matched
		data.CdnName = provider
	case "cloud":
		data.Cloud = matched
		data.CloudName = provider
	case "waf":
		data.Waf = matched
		data.WafName = provider
	}
	if r.shouldEmit(data) {
		output <- data
	}
}

// shouldEmit applies the provider match/filter options and the category
// flags to a classified record. It is shared by the per-address and the
// aggregate CIDR paths so both honor the same selection rules.
func (r *Runner) shouldEmit(data Output) bool {
	// Unmatched records are only emitted in exclude mode, which bypasses
	// this helper.
	if data.itemType == "" {
		return false
	}
	if skipped := filterIP(r.options, data); skipped {
		return false
	}
	if matched := matchIP(r.options, data); !matched {
		return false
	}
	switch {
	case r.options.Cdn && data.itemType == "cdn",
		r.options.Cloud && data.itemType == "cloud",
		r.options.Waf && data.itemType == "waf":
		return true
	case !r.options.Cdn && !r.options.Waf && !r.options.Cloud:
		return true
	}
	return false
}

// processCIDRAggregate classifies a CIDR input as minimal homogeneous CIDR
// blocks without enumerating addresses and feeds the resulting records through
// the existing category/provider filters and result callback.
func (r *Runner) processCIDRAggregate(item string, output chan Output) {
	blocks, err := r.cdnclient.CheckCIDR(item)
	if err != nil {
		if r.options.Verbose {
			gologger.Error().Msgf("Could not classify cidr %s: %s", item, err)
		}
		return
	}
	for _, block := range blocks {
		data := Output{
			aurora:       r.aurora,
			Timestamp:    time.Now(),
			Input:        item,
			IP:           block.Prefix.Addr().String(),
			Prefix:       block.Prefix.String(),
			AddressCount: block.AddressCount.String(),
			aggregate:    true,
			itemType:     block.ItemType,
		}
		switch block.ItemType {
		case "cdn":
			data.Cdn = true
			data.CdnName = block.Provider
		case "cloud":
			data.Cloud = true
			data.CloudName = block.Provider
		case "waf":
			data.Waf = true
			data.WafName = block.Provider
		}

		if r.options.Exclude {
			// Exclude mode emits the complement of the identified address
			// space: every unmatched block of the input prefix.
			if !block.Matched {
				output <- data
			}
			continue
		}
		if !block.Matched {
			continue
		}
		if r.shouldEmit(data) {
			output <- data
		}
	}
}

func matchIP(options *Options, data Output) bool {
	if len(options.MatchCdn) == 0 && len(options.MatchCloud) == 0 && len(options.MatchWaf) == 0 {
		return true
	}
	if len(options.MatchCdn) > 0 && data.itemType == "cdn" {
		matched := false
		for _, filter := range options.MatchCdn {
			if filter == data.CdnName {
				matched = true
			}
		}
		if matched {
			return true
		}
	}
	if len(options.MatchCloud) > 0 && data.itemType == "cloud" {
		matched := false
		for _, filter := range options.MatchCloud {
			if filter == data.CloudName {
				matched = true
			}
		}
		if matched {
			return true
		}
	}
	if len(options.MatchWaf) > 0 && data.itemType == "waf" {
		matched := false
		for _, filter := range options.MatchWaf {
			if filter == data.WafName {
				matched = true
			}
		}
		if matched {
			return true
		}
	}
	return false
}

func filterIP(options *Options, data Output) bool {
	if len(options.FilterCdn) == 0 && len(options.FilterCloud) == 0 && len(options.FilterWaf) == 0 {
		return false
	}
	if len(options.FilterCdn) > 0 && data.itemType == "cdn" {
		for _, filter := range options.FilterCdn {
			if filter == data.CdnName {
				return true
			}
		}
	}
	if len(options.FilterCloud) > 0 && data.itemType == "cloud" {
		for _, filter := range options.FilterCloud {
			if filter == data.CloudName {
				return true
			}
		}
	}
	if len(options.FilterWaf) > 0 && data.itemType == "waf" {
		for _, filter := range options.FilterWaf {
			if filter == data.WafName {
				return true
			}
		}
	}
	return false
}
