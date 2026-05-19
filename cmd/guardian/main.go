package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"

	"sub2api_guardian/internal/guardian"
)

func main() {
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)
	cfg, err := guardian.LoadConfig()
	if err != nil {
		log.Fatalf("config error: %v", err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	store, err := guardian.NewStore(ctx, cfg)
	if err != nil {
		log.Fatalf("db error: %v", err)
	}
	defer store.Close()
	auditor, err := guardian.NewAuditor(cfg.AuditDir)
	if err != nil {
		log.Fatalf("audit error: %v", err)
	}
	svc := guardian.NewService(cfg, store, guardian.NewSub2APIClient(cfg), guardian.NewOAuthRefresher(cfg), auditor)
	if cfg.WebEnabled {
		web := guardian.NewWebServer(cfg, store, auditor, svc)
		go func() {
			if err := web.Run(ctx); err != nil && ctx.Err() == nil {
				log.Printf("web panel stopped: %v", err)
			}
		}()
	}
	if err := svc.Run(ctx); err != nil && ctx.Err() == nil {
		log.Fatalf("guardian stopped: %v", err)
	}
}
