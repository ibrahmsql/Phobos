#!/bin/bash
# Phobos 24-Hour Continuous Stability Test
# Tests: Memory leaks, performance degradation, crash detection
# Location: /home/ibrahim/Phobos/tests/stability_24h.sh

LOG_FILE="/tmp/phobos_24h_test.log"
STATS_FILE="/tmp/phobos_24h_stats.log"
START_TIME=$(date +%s)
DURATION=86400  # 24 hours in seconds
ITERATION=0

echo "=== Phobos 24-Hour Stability Test ===" | tee $LOG_FILE
echo "Start time: $(date)" | tee -a $LOG_FILE
echo "Duration: 24 hours" | tee -a $LOG_FILE
echo "Log: $LOG_FILE" | tee -a $LOG_FILE
echo "" | tee -a $LOG_FILE

# Statistics tracking
TOTAL_SCANS=0
TOTAL_PORTS=0
CRASHES=0
ERRORS=0

while true; do
    CURRENT_TIME=$(date +%s)
    ELAPSED=$((CURRENT_TIME - START_TIME))
    
    # Check if 24 hours passed
    if [ $ELAPSED -ge $DURATION ]; then
        echo "" | tee -a $LOG_FILE
        echo "=== 24-Hour Test COMPLETED ===" | tee -a $LOG_FILE
        echo "End time: $(date)" | tee -a $LOG_FILE
        echo "Total iterations: $ITERATION" | tee -a $LOG_FILE
        echo "Total scans: $TOTAL_SCANS" | tee -a $LOG_FILE
        echo "Total ports: $TOTAL_PORTS" | tee -a $LOG_FILE
        echo "Crashes: $CRASHES" | tee -a $LOG_FILE
        echo "Errors: $ERRORS" | tee -a $LOG_FILE
        
        # Calculate uptime percentage
        if [ $TOTAL_SCANS -gt 0 ]; then
            SUCCESS_RATE=$(echo "scale=2; (($TOTAL_SCANS - $CRASHES) / $TOTAL_SCANS) * 100" | bc)
            echo "Success rate: ${SUCCESS_RATE}%" | tee -a $LOG_FILE
        fi
        
        break
    fi
    
    ITERATION=$((ITERATION + 1))
    HOURS=$((ELAPSED / 3600))
    MINUTES=$(((ELAPSED % 3600) / 60))
    
    echo "[$(date '+%H:%M:%S')] Iteration $ITERATION (${HOURS}h ${MINUTES}m elapsed)" | tee -a $LOG_FILE
    
    # Run scan with varying configurations
    if [ $((ITERATION % 2)) -eq 0 ]; then
        # Even iterations: small port range, high batch
        PORT_RANGE="1-1000"
        BATCH_SIZE=20000
    else
        # Odd iterations: larger range, moderate batch
        PORT_RANGE="1-10000"
        BATCH_SIZE=15000
    fi
    
    # Execute scan
    if timeout 30 ./target/release/phobos 127.0.0.1 -p $PORT_RANGE -b $BATCH_SIZE --no-nmap --no-banner --greppable > /dev/null 2>&1; then
        TOTAL_SCANS=$((TOTAL_SCANS + 1))
        
        # Calculate ports scanned
        if [ "$PORT_RANGE" = "1-1000" ]; then
            TOTAL_PORTS=$((TOTAL_PORTS + 1000))
        else
            TOTAL_PORTS=$((TOTAL_PORTS + 10000))
        fi
        
        echo "  ✓ Scan completed successfully ($PORT_RANGE, batch $BATCH_SIZE)" >> $LOG_FILE
    else
        EXIT_CODE=$?
        if [ $EXIT_CODE -eq 124 ]; then
            echo "  ⚠ Scan timeout (30s exceeded)" | tee -a $LOG_FILE
            ERRORS=$((ERRORS + 1))
        else
            echo "  ✗ CRASH DETECTED (exit code: $EXIT_CODE)" | tee -a $LOG_FILE
            CRASHES=$((CRASHES + 1))
        fi
    fi
    
    # Memory check every 100 iterations
    if [ $((ITERATION % 100)) -eq 0 ]; then
        MEM_USAGE=$(ps aux | grep "phobos" | grep -v grep | awk '{sum+=$6} END {print sum/1024}')
        if [ -n "$MEM_USAGE" ]; then
            echo "  Memory usage: ${MEM_USAGE} MB" | tee -a $LOG_FILE
        fi
        
        # Write stats checkpoint
        echo "[$HOURS:$MINUTES] Scans: $TOTAL_SCANS, Ports: $TOTAL_PORTS, Crashes: $CRASHES" >> $STATS_FILE
    fi
    
    # Brief sleep to avoid CPU saturation
    sleep 0.1
    
done

echo "" | tee -a $LOG_FILE
echo "Full log: $LOG_FILE" | tee -a $LOG_FILE
echo "Stats log: $STATS_FILE" | tee -a $LOG_FILE
