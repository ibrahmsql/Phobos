#!/bin/bash
# Benchmark: Phobos vs RustScan Performance Comparison
# This script compares scanning performance after RustScan optimizations

set -e

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "🚀 Phobos vs RustScan Performance Comparison"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

# Configuration
TARGET="${1:-127.0.0.1}"
PORTS="${2:-1-1000}"

echo "📋 Test Configuration:"
echo "  Target: $TARGET"
echo "  Ports:  $PORTS"
echo ""

# Check if Phobos binary exists
if [ ! -f "./target/release/phobos" ]; then
    echo "❌ Phobos binary not found. Building..."
    cargo build --release
fi

# Function to run Phobos scan
run_phobos() {
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "🔍 Running Phobos Scan (with RustScan optimizations)"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    
    START_TIME=$(date +%s.%N)
    ./target/release/phobos -a "$TARGET" -p "$PORTS" --timeout 1000 > /tmp/phobos_results.txt 2>&1 || true
    END_TIME=$(date +%s.%N)
    
    PHOBOS_TIME=$(echo "$END_TIME - $START_TIME" | bc)
    
    # Extract metrics from output
    OPEN_PORTS=$(grep -c "OPEN" /tmp/phobos_results.txt 2>/dev/null || echo "0")
    
    echo ""
    echo "✅ Phobos Results:"
    echo "  ⏱️  Time:       ${PHOBOS_TIME}s"
    echo "  🔓 Open ports: $OPEN_PORTS"
    
    if [ "$PORTS" = "1-1000" ]; then
        TOTAL_PORTS=1000
    else
        # Extract port count from range
        TOTAL_PORTS=$(echo "$PORTS" | awk -F'-' '{print $2 - $1 + 1}')
    fi
    
    PHOBOS_RATE=$(echo "scale=2; $TOTAL_PORTS / $PHOBOS_TIME" | bc)
    echo "  ⚡ Scan rate:  ${PHOBOS_RATE} ports/sec"
    echo ""
}

# Function to run RustScan (if installed)
run_rustscan() {
    if command -v rustscan &> /dev/null; then
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        echo "🦀 Running RustScan"
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        
        START_TIME=$(date +%s.%N)
        rustscan -a "$TARGET" --range "$PORTS" --timeout 1000 --scripts none > /tmp/rustscan_results.txt 2>&1 || true
        END_TIME=$(date +%s.%N)
        
        RUSTSCAN_TIME=$(echo "$END_TIME - $START_TIME" | bc)
        RUSTSCAN_OPEN=$(grep -c "Open" /tmp/rustscan_results.txt 2>/dev/null || echo "0")
        
        echo ""
        echo "✅ RustScan Results:"
        echo "  ⏱️  Time:       ${RUSTSCAN_TIME}s"
        echo "  🔓 Open ports: $RUSTSCAN_OPEN"
        
        if [ "$PORTS" = "1-1000" ]; then
            TOTAL_PORTS=1000
        else
            TOTAL_PORTS=$(echo "$PORTS" | awk -F'-' '{print $2 - $1 + 1}')
        fi
        
        RUSTSCAN_RATE=$(echo "scale=2; $TOTAL_PORTS / $RUSTSCAN_TIME" | bc)
        echo "  ⚡ Scan rate:  ${RUSTSCAN_RATE} ports/sec"
        echo ""
        
        # Calculate speedup
        SPEEDUP=$(echo "scale=2; $RUSTSCAN_TIME / $PHOBOS_TIME" | bc)
        
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        echo "📊 Performance Comparison"
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        echo ""
        
        if (( $(echo "$SPEEDUP > 1" | bc -l) )); then
            echo "🏆 Phobos is ${SPEEDUP}x FASTER than RustScan!"
        elif (( $(echo "$SPEEDUP < 1" | bc -l) )); then
            INVERSE=$(echo "scale=2; 1 / $SPEEDUP" | bc)
            echo "⚠️  RustScan is ${INVERSE}x faster than Phobos"
        else
            echo "🤝 Phobos and RustScan have similar performance"
        fi
        
        echo ""
        echo "Performance details:"
        echo "  Phobos:   ${PHOBOS_TIME}s (${PHOBOS_RATE} ports/sec)"
        echo "  RustScan: ${RUSTSCAN_TIME}s (${RUSTSCAN_RATE} ports/sec)"
        echo ""
    else
        echo "⚠️  RustScan not installed - install with: cargo install rustscan"
        echo "   Skipping comparison..."
        echo ""
    fi
}

# Function to show system limits
show_limits() {
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "🖥️  System Limits"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo ""
    
    if command -v ulimit &> /dev/null; then
        ULIMIT=$(ulimit -n)
        echo "  File descriptors: $ULIMIT"
        
        # Calculate optimal batch size (like RustScan)
        AVAILABLE=$((ULIMIT - 250))
        OPTIMAL=$(echo "scale=0; $AVAILABLE * 0.8 / 1" | bc)
        
        echo "  Optimal batch:    $OPTIMAL"
        echo ""
        
        if [ "$ULIMIT" -lt 10000 ]; then
            echo "⚠️  Low ulimit detected! For maximum performance, run:"
            echo "   ulimit -n 65535"
            echo ""
        fi
    fi
}

# Main execution
show_limits
run_phobos
run_rustscan

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "✅ Benchmark Complete"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "💡 Tips:"
echo "  • Increase ulimit for better performance: ulimit -n 65535"
echo "  • Test different port ranges: ./benchmark_rustscan_comparison.sh 127.0.0.1 1-10000"
echo "  • Check system load: htop or top while scanning"
echo ""

# Cleanup
rm -f /tmp/phobos_results.txt /tmp/rustscan_results.txt
