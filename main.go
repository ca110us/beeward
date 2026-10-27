package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"golang.org/x/sync/errgroup"

	"github.com/ca110us/beeward/pkg/metrics"
	"github.com/ca110us/beeward/pkg/nfs"
	"github.com/ca110us/beeward/pkg/xdpratelimit"
)

func main() {
	log.SetFlags(log.Ldate | log.Ltime | log.Lmicroseconds)

	nodeName := os.Getenv("NODE_NAME")
	if nodeName == "" {
		nodeName = "unknown"
	}
	log.Printf("Starting Beeward on node: %s", nodeName)

	// Setup signal handler
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigCh
		log.Println("Received shutdown signal")
		cancel()
	}()

	// Start HTTP server for metrics (shared by all modules)
	metricsPort := os.Getenv("METRICS_PORT")
	if metricsPort == "" {
		metricsPort = "9100"
	}

	go func() {
		log.Printf("Starting metrics server on :%s", metricsPort)
		if err := metrics.StartServer(metricsPort); err != nil {
			log.Fatalf("Failed to start metrics server: %v", err)
		}
	}()

	g, ctx := errgroup.WithContext(ctx)

	// NFS Monitor Module
	g.Go(func() error {
		monitor, err := nfs.NewMonitor(nodeName)
		if err != nil {
			log.Printf("WARNING: Failed to create NFS monitor: %v", err)
			return nil // Non-fatal: don't crash other modules
		}
		defer monitor.Close()

		interval := 60 * time.Second
		if envInterval := os.Getenv("MONITOR_INTERVAL"); envInterval != "" {
			if d, err := time.ParseDuration(envInterval); err == nil {
				interval = d
			}
		}

		if err := monitor.Run(ctx, interval); err != nil {
			log.Printf("NFS monitor error: %v", err)
		}
		return nil
	})

	// XDP Rate Limiter Module (conditional)
	if os.Getenv("XDP_ENABLED") == "true" {
		g.Go(func() error {
			if err := xdpratelimit.Run(ctx); err != nil {
				log.Printf("WARNING: XDP Rate Limiter failed: %v", err)
			}
			return nil // Non-fatal: don't crash other modules
		})
	}

	if err := g.Wait(); err != nil {
		log.Fatalf("Fatal error: %v", err)
	}
}
