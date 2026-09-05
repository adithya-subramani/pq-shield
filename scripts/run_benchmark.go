//go:build ignore

package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"net/http"
	"sync"
	"sync/atomic"
	"time"
)

func main() {
	targetURL := flag.String("url", "https://localhost:8443/", "Target URL for benchmark")
	qps := flag.Int("qps", 10000, "Target requests per second")
	duration := flag.Duration("duration", 30*time.Second, "Duration of the benchmark")
	concurrency := flag.Int("c", 200, "Number of concurrent workers")
	flag.Parse()

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS13,
			MaxVersion:         tls.VersionTLS13,
			// CurvePreferences: []tls.CurveID{tls.X25519MLKEM768}, // Uncomment if go1.24+ PQC curve is enabled
		},
		MaxIdleConns:        *concurrency,
		MaxIdleConnsPerHost: *concurrency,
		IdleConnTimeout:     90 * time.Second,
		DisableCompression:  true,
	}

	client := &http.Client{
		Transport: tr,
		Timeout:   10 * time.Second,
	}

	fmt.Printf("=== Starting PQC Benchmark ===\n")
	fmt.Printf("Target: %s | Target QPS: %d | Duration: %v | Workers: %d\n\n", *targetURL, *qps, *duration, *concurrency)

	var successCount uint64
	var failCount uint64
	var totalLatencyNs uint64

	ticker := time.NewTicker(time.Second / time.Duration(*qps))
	defer ticker.Stop()

	stopTimer := time.NewTimer(*duration)
	defer stopTimer.Stop()

	jobs := make(chan struct{}, *qps)
	var wg sync.WaitGroup

	// Worker pool
	for i := 0; i < *concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range jobs {
				start := time.Now()
				resp, err := client.Get(*targetURL)
				latency := time.Since(start)

				if err == nil && (resp.StatusCode == 200 || resp.StatusCode == 502) {
					resp.Body.Close()
					atomic.AddUint64(&successCount, 1)
					atomic.AddUint64(&totalLatencyNs, uint64(latency.Nanoseconds()))
				} else {
					if resp != nil {
						resp.Body.Close()
					}
					atomic.AddUint64(&failCount, 1)
				}
			}
		}()
	}

	startTime := time.Now()

Loop:
	for {
		select {
		case <-stopTimer.C:
			break Loop
		case <-ticker.C:
			select {
			case jobs <- struct{}{}:
			default:
				// Worker queue saturated
			}
		}
	}

	close(jobs)
	wg.Wait()
	totalTime := time.Since(startTime)

	totalRequests := successCount + failCount
	actualQPS := float64(totalRequests) / totalTime.Seconds()
	avgLatency := time.Duration(0)
	if successCount > 0 {
		avgLatency = time.Duration(totalLatencyNs / successCount)
	}

	fmt.Printf("=== Benchmark Results ===\n")
	fmt.Printf("Elapsed Time:   %.2fs\n", totalTime.Seconds())
	fmt.Printf("Total Requests: %d\n", totalRequests)
	fmt.Printf("Successful:     %d\n", successCount)
	fmt.Printf("Failed:         %d\n", failCount)
	fmt.Printf("Throughput:     %.2f req/s\n", actualQPS)
	fmt.Printf("Avg Latency:    %v\n", avgLatency)
}
