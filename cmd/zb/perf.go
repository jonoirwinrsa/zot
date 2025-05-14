package main

import (
	crand "crypto/rand"
	"crypto/tls"
	"fmt"
	"log"
	"math/big"
	"net"
	"net/http"
	urlparser "net/url"
	"os"
	"path"
	"sort"
	"strings"
	"sync"
	"text/tabwriter"
	"time"

	godigest "github.com/opencontainers/go-digest"
	"gopkg.in/resty.v1"

	"zotregistry.dev/zot/pkg/api/constants"
)

const (
	KiB                  = 1 * 1024
	MiB                  = 1 * KiB * 1024
	GiB                  = 1 * MiB * 1024
	maxSize              = 1 * GiB // 1GiB
	defaultDirPerms      = 0o700
	defaultFilePerms     = 0o600
	defaultSchemaVersion = 2
	smallBlob            = 1 * MiB
	mediumBlob           = 10 * MiB
	largeBlob            = 100 * MiB
	cicdFmt              = "ci-cd"
	secureProtocol       = "https"
	httpKeepAlive        = 30 * time.Second
	maxSourceIPs         = 1000
	httpTimeout          = 30 * time.Second
	TLSHandshakeTimeout  = 10 * time.Second
)

//nolint:gochecknoglobals
var blobHash map[string]godigest.Digest = map[string]godigest.Digest{}

//nolint:gochecknoglobals // used only in this test
var statusRequests sync.Map

func setup(workingDir string) {
	_ = os.MkdirAll(workingDir, defaultDirPerms)

	const multiplier = 10

	const rndPageSize = 4 * KiB

	for size := 1 * MiB; size < maxSize; size *= multiplier {
		fname := path.Join(workingDir, fmt.Sprintf("%d.blob", size))

		fhandle, err := os.OpenFile(fname, os.O_RDWR|os.O_CREATE|os.O_TRUNC, defaultFilePerms)
		if err != nil {
			log.Fatal(err)
		}

		err = fhandle.Truncate(int64(size))
		if err != nil {
			log.Fatal(err)
		}

		_, err = fhandle.Seek(0, 0)
		if err != nil {
			log.Fatal(err)
		}

		// write a random first page so every test run has different blob content
		rnd := make([]byte, rndPageSize)
		if _, err := crand.Read(rnd); err != nil {
			log.Fatal(err)
		}

		if _, err := fhandle.Write(rnd); err != nil {
			log.Fatal(err)
		}

		if _, err := fhandle.Seek(0, 0); err != nil {
			log.Fatal(err)
		}

		fhandle.Close() // should flush the write

		// pre-compute the SHA256
		fhandle, err = os.OpenFile(fname, os.O_RDONLY, defaultFilePerms)
		if err != nil {
			log.Fatal(err)
		}

		defer fhandle.Close()

		digest, err := godigest.FromReader(fhandle)
		if err != nil {
			log.Fatal(err) //nolint:gocritic // file closed on exit
		}

		blobHash[fname] = digest
	}
}

func teardown(workingDir string) {
	_ = os.RemoveAll(workingDir)
}

// statistics handling.

type Durations []time.Duration

func (a Durations) Len() int           { return len(a) }
func (a Durations) Swap(i, j int)      { a[i], a[j] = a[j], a[i] }
func (a Durations) Less(i, j int) bool { return a[i] < a[j] }

type statsSummary struct {
	latencies            []time.Duration
	name                 string
	min, max, total      time.Duration
	statusHist           map[string]int
	rps                  float32
	throughputMBps       float32
	mixedSize, mixedType bool
	errorCount           int
	errors               map[string]int
}

func newStatsSummary(name string) statsSummary {
	summary := statsSummary{
		name:       name,
		min:        -1,
		max:        -1,
		statusHist: make(map[string]int),
		mixedSize:  false,
		mixedType:  false,
	}

	return summary
}

type statsRecord struct {
	latency    time.Duration
	statusCode int
	isConnFail bool
	isErr      bool
	err        error
}

func updateStats(summary *statsSummary, record statsRecord) {
	if record.isConnFail || record.isErr {
		summary.errorCount++
	}

	if record.err != nil {
		summary.errors[record.err.Error()] += 1
	}

	if summary.min < 0 || record.latency < summary.min {
		summary.min = record.latency
	}

	if summary.max < 0 || record.latency > summary.max {
		summary.max = record.latency
	}

	// 2xx
	if record.statusCode >= http.StatusOK &&
		record.statusCode <= http.StatusAccepted {
		summary.statusHist["2xx"]++
	}

	// 3xx
	if record.statusCode >= http.StatusMultipleChoices &&
		record.statusCode <= http.StatusPermanentRedirect {
		summary.statusHist["3xx"]++
	}

	// 4xx
	if record.statusCode >= http.StatusBadRequest &&
		record.statusCode <= http.StatusUnavailableForLegalReasons {
		summary.statusHist["4xx"]++
	}

	// 5xx
	if record.statusCode >= http.StatusInternalServerError &&
		record.statusCode <= http.StatusNetworkAuthenticationRequired {
		summary.statusHist["5xx"]++
	}

	summary.latencies = append(summary.latencies, record.latency)
}

type cicdTestSummary struct {
	Name          string  `json:"name"`
	RPS           float32 `json:"rps"`
	ThroughputMBs float32 `json:"throughputMBs"`
	NumberOfReqs  int     `json:"numberOfReqs"`
}

type manifestStruct struct {
	manifestHash       map[string]string
	manifestBySizeHash map[int](map[string]string)
}

//nolint:gochecknoglobals // used only in this test
var results = make(map[string]map[string]float32) // test name -> url -> throughputMBps

func printStats(requests int, summary *statsSummary, config testConfig, outFmt string, url string) {
	log.Printf("============\n")
	log.Printf("Test name:\t%s", summary.name)
	log.Printf("Time taken for tests:\t%v", summary.total)
	log.Printf("Requests per second:\t%v", summary.rps)
	if summary.total > 0 {
		summary.throughputMBps = float32(requests) * float32(config.size) / float32(MiB) / float32(summary.total.Seconds())
	}
	log.Printf("Throughput MB/s:\t%v", summary.throughputMBps)
	log.Printf("Complete requests:\t%v", requests-summary.errorCount)
	log.Printf("Failed requests:\t%v", summary.errorCount)

	for errStr, count := range summary.errors {
		log.Printf("Error %s count:\t%d", errStr, count)
	}

	log.Printf("\n")

	if summary.mixedSize {
		current := loadOrStore(&statusRequests, "1MB", 0)
		log.Printf("1MB:\t%v", current)

		current = loadOrStore(&statusRequests, "10MB", 0)
		log.Printf("10MB:\t%v", current)

		current = loadOrStore(&statusRequests, "100MB", 0)
		log.Printf("100MB:\t%v", current)

		log.Printf("\n")
	}

	if summary.mixedType {
		pull := loadOrStore(&statusRequests, "Pull", 0)
		log.Printf("Pull:\t%v", pull)

		push := loadOrStore(&statusRequests, "Push", 0)
		log.Printf("Push:\t%v", push)

		log.Printf("\n")
	}

	for k, v := range summary.statusHist {
		log.Printf("%s responses:\t%v", k, v)
	}

	log.Printf("\n")
	log.Printf("min: %v", summary.min)
	log.Printf("max: %v", summary.max)
	log.Printf("%s:\t%v", "p50", summary.latencies[requests/2])
	log.Printf("%s:\t%v", "p75", summary.latencies[requests*3/4])
	log.Printf("%s:\t%v", "p90", summary.latencies[requests*9/10])
	log.Printf("%s:\t%v", "p99", summary.latencies[requests*99/100])
	log.Printf("\n")

	// ci/cd
	if outFmt == cicdFmt {
		// Store result in in-memory map
		if _, ok := results[summary.name]; !ok {
			results[summary.name] = make(map[string]float32)
		}
		results[summary.name][url] = summary.throughputMBps
	}
}

// test suites/funcs.

type testFunc func(
	workdir, url, repo string,
	requests int,
	config testConfig,
	statsCh chan statsRecord,
	client *resty.Client,
	skipCleanup bool,
) error

//nolint:gosec
func GetCatalog(
	workdir, url, repo string,
	requests int,
	config testConfig,
	statsCh chan statsRecord,
	client *resty.Client,
	skipCleanup bool,
) error {
	var repos []string

	var err error

	statusRequests = sync.Map{}

	for count := 0; count < requests; count++ {
		// Push random blob
		_, repos, err = pushMonolithImage(workdir, url, repo, repos, config, client)
		if err != nil {
			return err
		}
	}

	for count := 0; count < requests; count++ {
		func() {
			start := time.Now()

			var isConnFail, isErr bool

			var statusCode int

			var latency time.Duration

			var err error

			defer func() {
				// send a stats record
				statsCh <- statsRecord{
					latency:    latency,
					statusCode: statusCode,
					isConnFail: isConnFail,
					isErr:      isErr,
					err:        err,
				}
			}()

			// send request and get response
			resp, err := client.R().Get(url + constants.RoutePrefix + constants.ExtCatalogPrefix)

			latency = time.Since(start)

			if err != nil {
				isConnFail = true

				return
			}

			// request specific check
			statusCode = resp.StatusCode()
			if statusCode != http.StatusOK {
				isErr = true

				return
			}
		}()
	}

	// clean up
	if !skipCleanup {
		err = deleteTestRepo(repos, url, client)
		if err != nil {
			return err
		}
	}

	return nil
}

func PushMonolithStreamed(
	workdir, url, trepo string,
	requests int,
	config testConfig,
	statsCh chan statsRecord,
	client *resty.Client,
	skipCleanup bool,
) error {
	var repos []string

	if config.mixedSize {
		statusRequests = sync.Map{}
	}

	for count := 0; count < requests; count++ {
		repos = pushMonolithAndCollect(workdir, url, trepo, count,
			repos, config, client, statsCh)
	}

	// clean up
	if !skipCleanup {
		err := deleteTestRepo(repos, url, client)
		if err != nil {
			return err
		}
	}

	return nil
}

func PushChunkStreamed(
	workdir, url, trepo string,
	requests int,
	config testConfig,
	statsCh chan statsRecord,
	client *resty.Client,
	skipCleanup bool,
) error {
	var repos []string

	if config.mixedSize {
		statusRequests = sync.Map{}
	}

	for count := 0; count < requests; count++ {
		repos = pushChunkAndCollect(workdir, url, trepo, count,
			repos, config, client, statsCh)
	}

	// clean up
	if !skipCleanup {
		err := deleteTestRepo(repos, url, client)
		if err != nil {
			return err
		}
	}

	return nil
}

func Pull(
	workdir, url, trepo string,
	requests int,
	config testConfig,
	statsCh chan statsRecord,
	client *resty.Client,
	skipCleanup bool,
) error {
	var repos []string

	var manifestHash map[string]string

	manifestBySizeHash := make(map[int](map[string]string))

	if config.mixedSize {
		statusRequests = sync.Map{}
	}

	if config.mixedSize {
		var manifestBySize map[string]string

		smallSizeIdx := 0
		mediumSizeIdx := 1
		largeSizeIdx := 2

		config.size = smallBlob

		// Push small blob
		manifestBySize, repos, err := pushMonolithImage(workdir, url, trepo, repos, config, client)
		if err != nil {
			return err
		}

		manifestBySizeHash[smallSizeIdx] = manifestBySize

		config.size = mediumBlob

		// Push medium blob
		manifestBySize, repos, err = pushMonolithImage(workdir, url, trepo, repos, config, client)
		if err != nil {
			return err
		}

		manifestBySizeHash[mediumSizeIdx] = manifestBySize

		config.size = largeBlob

		// Push large blob
		//nolint: ineffassign, staticcheck, wastedassign
		manifestBySize, repos, err = pushMonolithImage(workdir, url, trepo, repos, config, client)
		if err != nil {
			return err
		}

		manifestBySizeHash[largeSizeIdx] = manifestBySize
	} else {
		// Push blob given size
		var err error

		manifestHash, repos, err = pushMonolithImage(workdir, url, trepo, repos, config, client)
		if err != nil {
			return err
		}
	}

	manifestItem := manifestStruct{
		manifestHash:       manifestHash,
		manifestBySizeHash: manifestBySizeHash,
	}

	// download image
	for count := 0; count < requests; count++ {
		repos = pullAndCollect(url, repos, manifestItem, config, client, statsCh)
	}

	// clean up
	if !skipCleanup {
		err := deleteTestRepo(repos, url, client)
		if err != nil {
			return err
		}
	}

	return nil
}

// test driver.

type testConfig struct {
	name  string
	tfunc testFunc
	// test-specific params
	size                 int
	probabilityRange     []float64
	mixedSize, mixedType bool
}

var testSuite = []testConfig{ //nolint:gochecknoglobals // used only in this test
	{
		name:             "Get Catalog",
		tfunc:            GetCatalog,
		probabilityRange: normalizeProbabilityRange([]float64{0.7, 0.2, 0.1}),
	},
	{
		name:  "Push Monolith 1MB",
		tfunc: PushMonolithStreamed,
		size:  smallBlob,
	},
	{
		name:  "Push Monolith 10MB",
		tfunc: PushMonolithStreamed,
		size:  mediumBlob,
	},
	{
		name:  "Push Monolith 100MB",
		tfunc: PushMonolithStreamed,
		size:  largeBlob,
	},
	{
		name:  "Push Chunk Streamed 1MB",
		tfunc: PushChunkStreamed,
		size:  smallBlob,
	},
	{
		name:  "Push Chunk Streamed 10MB",
		tfunc: PushChunkStreamed,
		size:  mediumBlob,
	},
	{
		name:  "Push Chunk Streamed 100MB",
		tfunc: PushChunkStreamed,
		size:  largeBlob,
	},
	{
		name:  "Pull 1MB",
		tfunc: Pull,
		size:  smallBlob,
	},
	{
		name:  "Pull 10MB",
		tfunc: Pull,
		size:  mediumBlob,
	},
	{
		name:  "Pull 100MB",
		tfunc: Pull,
		size:  largeBlob,
	},
}

func Perf(
	workdir, url, auth, repo string,
	concurrency int, requests int,
	outFmt string, srcIPs string, srcCIDR string, skipCleanup bool,
) {
	// logging
	log.SetFlags(0)
	log.SetOutput(tabwriter.NewWriter(os.Stdout, 0, 0, 1, ' ', tabwriter.TabIndent))

	// common header
	log.Printf("Registry URL:\t%s", url)
	log.Printf("\n")
	log.Printf("Concurrency Level:\t%v", concurrency)
	log.Printf("Total requests:\t%v", requests)

	if workdir == "" {
		cwd, err := os.Getwd()
		if err != nil {
			log.Fatal("unable to get current working dir")
		}

		log.Printf("Working dir:\t%v", cwd)
	} else {
		log.Printf("Working dir:\t%v", workdir)
	}

	log.Printf("\n")

	// initialize test data
	log.Printf("Preparing test data ...\n")

	setup(workdir)
	defer teardown(workdir)

	log.Printf("Starting tests ...\n")

	var err error

	zbError := false

	// get host ips from command line to make requests from
	var ips []string
	if len(srcIPs) > 0 {
		ips = strings.Split(srcIPs, ",")
	} else if len(srcCIDR) > 0 {
		ips, err = getIPsFromCIDR(srcCIDR, maxSourceIPs)
		if err != nil {
			log.Fatal(err) //nolint: gocritic
		}
	}

	for _, tconfig := range testSuite {
		statsCh := make(chan statsRecord, requests)

		var wg sync.WaitGroup

		summary := newStatsSummary(tconfig.name)

		start := time.Now()

		for c := 0; c < concurrency; c++ {
			// parallelize with clients
			wg.Add(1)

			go func() {
				defer wg.Done()

				httpClient, err := getRandomClientIPs(auth, url, ips)
				if err != nil {
					log.Fatal(err)
				}

				err = tconfig.tfunc(workdir, url, repo, requests/concurrency, tconfig, statsCh, httpClient, skipCleanup)
				if err != nil {
					log.Fatal(err)
				}
			}()
		}

		wg.Wait()

		summary.total = time.Since(start)
		summary.rps = float32(requests) / float32(summary.total.Seconds())

		if tconfig.mixedSize || tconfig.size == 0 {
			summary.mixedSize = true
		}

		if tconfig.mixedType {
			summary.mixedType = true
		}

		for count := 0; count < requests; count++ {
			record := <-statsCh
			updateStats(&summary, record)
		}

		sort.Sort(Durations(summary.latencies))

		printStats(requests, &summary, tconfig, outFmt, url)

		if summary.errorCount != 0 && !zbError {
			zbError = true
		}
	}

	// After all tests, if cicdFmt, write CSV of results
	if outFmt == cicdFmt {
		// Prepare CSV header and row (flipped layout: URL as row, test names as columns)

		// Ensure we know all test names from the testSuite
		var testNames []string
		for _, t := range testSuite {
			testNames = append(testNames, t.name)
		}
		sort.Strings(testNames)

		// Collect all URLs
		urlSet := make(map[string]struct{})
		for _, urlMap := range results {
			for u := range urlMap {
				urlSet[u] = struct{}{}
			}
		}
		var urls []string
		for u := range urlSet {
			urls = append(urls, u)
		}
		sort.Strings(urls)

		filename := "all_results.csv"
		var file *os.File
		if _, err := os.Stat(filename); os.IsNotExist(err) {
			// Create and write header
			file, err = os.Create(filename)
			if err != nil {
				log.Fatal(err)
			}
			defer file.Close()

			header := append([]string{"URL"}, testNames...)
			fmt.Fprintln(file, strings.Join(header, ","))
		} else {
			// Open file in append mode
			file, err = os.OpenFile(filename, os.O_APPEND|os.O_WRONLY, defaultFilePerms)
			if err != nil {
				log.Fatal(err)
			}
			defer file.Close()
		}

		for _, u := range urls {
			row := make([]string, 0, len(testNames)+1)
			row = append(row, u)
			for _, tn := range testNames {
				val, ok := results[tn][u]
				if ok {
					row = append(row, fmt.Sprintf("%.2f", val))
				} else {
					row = append(row, "")
				}
			}
			fmt.Fprintln(file, strings.Join(row, ","))
		}
	}

	if zbError {
		os.Exit(1)
	}
}

// getRandomClientIPs returns a resty client with a random bind address from ips slice.
func getRandomClientIPs(auth string, url string, ips []string) (*resty.Client, error) {
	client := resty.New()

	if auth != "" {
		creds := strings.Split(auth, ":")
		client.SetBasicAuth(creds[0], creds[1])
	}

	// get random ip client
	if len(ips) != 0 {
		// get random number
		nBig, err := crand.Int(crand.Reader, big.NewInt(int64(len(ips))))
		if err != nil {
			return nil, err
		}

		// get random ip
		ip := ips[nBig.Int64()]

		// set ip in transport
		localAddr, err := net.ResolveTCPAddr("tcp", ip+":0")
		if err != nil {
			return nil, err
		}

		transport := &http.Transport{
			Proxy: http.ProxyFromEnvironment,
			DialContext: (&net.Dialer{
				Timeout:   httpTimeout,
				KeepAlive: httpKeepAlive,
				LocalAddr: localAddr,
			}).DialContext,
			TLSHandshakeTimeout: TLSHandshakeTimeout,
		}

		client.SetTransport(transport)
	}

	parsedURL, err := urlparser.Parse(url)
	if err != nil {
		log.Fatal(err)
	}

	//nolint: gosec
	if parsedURL.Scheme == secureProtocol {
		client.SetTLSClientConfig(&tls.Config{InsecureSkipVerify: true})
	}

	return client, nil
}

// getIPsFromCIDR returns a list of ips given a cidr.
func getIPsFromCIDR(cidr string, maxIPs int) ([]string, error) {
	//nolint:varnamelen
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}

	var ips []string
	for ip := ip.Mask(ipnet.Mask); ipnet.Contains(ip) && len(ips) < maxIPs; inc(ip) {
		ips = append(ips, ip.String())
	}
	// remove network address and broadcast address
	return ips[1 : len(ips)-1], nil
}

// https://go.dev/play/p/sdzcMvZYWnc
func inc(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}
