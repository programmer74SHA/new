package scheduler

import (
	"context"
	"log"
	"sync"
	"time"

	"gitlab.apk-group.net/siem/backend/asset-discovery/internal/scheduler/port"
)

// SchedulerRunner is responsible for periodically checking and executing scheduled scans
type SchedulerRunner struct {
	service       port.Service
	checkInterval time.Duration
	running       bool
	stopChan      chan struct{}
	wg            sync.WaitGroup
}

// NewSchedulerRunner creates a new scheduler runner
func NewSchedulerRunner(service port.Service, checkInterval time.Duration) *SchedulerRunner {
	return &SchedulerRunner{
		service:       service,
		checkInterval: checkInterval,
		running:       false,
		stopChan:      make(chan struct{}),
	}
}

// Start begins the scheduler runner
func (r *SchedulerRunner) Start() {
	if r.running {
		log.Println("Scheduler Runner: Already running")
		return
	}

	r.running = true
	r.wg.Add(1)

	log.Printf("Scheduler Runner: Starting with check interval of %s", r.checkInterval)

	go func() {
		defer r.wg.Done()
		ticker := time.NewTicker(r.checkInterval)
		defer ticker.Stop()

		// Run once at startup
		r.checkAndExecuteSchedules()

		for {
			select {
			case <-ticker.C:
				r.checkAndExecuteSchedules()
			case <-r.stopChan:
				log.Println("Scheduler Runner: Stopping")
				return
			}
		}
	}()
}

// Stop halts the scheduler runner
func (r *SchedulerRunner) Stop() {
	if !r.running {
		return
	}

	log.Println("Scheduler Runner: Stopping")
	close(r.stopChan)
	r.wg.Wait()
	r.running = false
}

// checkAndExecuteSchedules checks for due schedules and executes them
func (r *SchedulerRunner) checkAndExecuteSchedules() {
	ctx := context.Background()

	log.Println("Scheduler Runner: Checking for due schedules")

	schedules, err := r.service.GetDueSchedules(ctx)
	if err != nil {
		log.Printf("Scheduler Runner: Error getting due schedules: %v", err)
		return
	}

	log.Printf("Scheduler Runner: Found %d due schedules", len(schedules))

	for _, schedule := range schedules {
		err := r.service.ExecuteScheduledScan(ctx, schedule)
		if err != nil {
			log.Printf("Scheduler Runner: Error executing schedule for scanner ID %d: %v",
				schedule.Scanner.ID, err)
			continue
		}

		log.Printf("Scheduler Runner: Successfully executed schedule for scanner ID: %d",
			schedule.Scanner.ID)
	}
}
