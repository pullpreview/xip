package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/pullpreview/docker-sslip/internal/config"
	"github.com/pullpreview/docker-sslip/internal/dnsserver"
	"github.com/pullpreview/docker-sslip/internal/metrics"
)

func main() {
	textHandler := slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{})
	logger := slog.New(textHandler)

	cfg, err := config.Load(os.Args[1:])
	if err != nil {
		fmt.Fprintf(os.Stderr, "xip: %v\n", err)
		os.Exit(2)
	}

	logHandler, shutdownLogs, err := metrics.NewOTELLogHandler(context.Background(), logger)
	if err != nil {
		logger.Error("failed to initialize otel logs", "error", err)
		os.Exit(1)
	}
	if logHandler != nil {
		logger = slog.New(metrics.NewMultiHandler(textHandler, logHandler))
	}
	if shutdownLogs != nil {
		defer func() {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if err := shutdownLogs(ctx); err != nil {
				logger.Error("failed to flush otel logs", "error", err)
			}
		}()
	}

	metricsRecorder, shutdownMetrics, err := metrics.NewDNSRequestRecorder(context.Background(), logger)
	if err != nil {
		logger.Error("failed to initialize otel metrics", "error", err)
		os.Exit(1)
	}
	if shutdownMetrics != nil {
		defer func() {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if err := shutdownMetrics(ctx); err != nil {
				logger.Error("failed to flush otel metrics", "error", err)
			}
		}()
	}

	server := dnsserver.New(cfg, logger, metricsRecorder)

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	logger.Info("starting xip",
		"domain", cfg.Domain,
		"listen_udp", cfg.ListenUDP,
		"listen_tcp", cfg.ListenTCP,
		"listen_http", cfg.ListenHTTP,
		"listen_https", cfg.ListenHTTPS,
		"root_addresses", cfg.RootAddresses,
		"ns_addresses", cfg.NSAddresses,
		"blocklist_path", cfg.BlocklistPath,
		"blocklist_reload_interval", cfg.BlocklistReloadInterval,
	)

	if err := server.Start(ctx); err != nil {
		logger.Error("xip stopped with an error", "error", err)
		os.Exit(1)
	}

	logger.Info("xip stopped")
}
