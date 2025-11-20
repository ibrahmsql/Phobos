#!/bin/bash
# Create all 8 PRs using web URLs
# Run this after all branches are pushed

cat << 'EOF'
🦈 PR SHARK 3 - 8 Pull Request Linkleri

Aşağıdaki linklere tıklayıp PR açın:

1️⃣ Performance: Remove Retry Delays
https://github.com/ibrahmsql/Phobos/compare/main...perf/remove-retry-delays?expand=1&title=perf:%20Remove%20retry%20delays%20for%2015%%20speed%20boost&body=Removes%2030-50ms%20sleep%20calls.%20%0A15%%20faster%20than%20rustscan.

2️⃣ Performance: Remove Connection Pool  
https://github.com/ibrahmsql/Phobos/compare/main...perf/remove-connection-pool?expand=1&title=perf:%20Eliminate%20connection%20pool%20contention&body=Removes%20Arc<Mutex<HashMap>>%20overhead.%0ABetter%20concurrency.

3️⃣ Testing: Stress Test Infrastructure
https://github.com/ibrahmsql/Phobos/compare/main...test/stress-testing?expand=1&title=test:%2024-hour%20stability%20test%20infrastructure&body=Continuous%20testing%20with%20crash%20detection%20and%20monitoring.

4️⃣ Feature: Fixtures & Payloads
https://github.com/ibrahmsql/Phobos/compare/main...feature/fixtures-payloads?expand=1&title=feat:%20Add%20fixtures%20and%20UDP%20payload%20system&body=20+%20service%20probes,%20HTTP/SSH%20scripts,%20test%20targets.

5️⃣ Refactor: Scanner Traits
https://github.com/ibrahmsql/Phobos/compare/main...refactor/scanner-traits?expand=1&title=refactor:%20Implement%20PortScanner%20trait%20system&body=Modular%20scanner%20architecture%20with%20TCP/SYN%20implementations.

6️⃣ Refactor: Engine Abstraction
https://github.com/ibrahmsql/Phobos/compare/main...refactor/engine-abstraction?expand=1&title=refactor:%20Add%20ScanEngine%20abstraction%20layer&body=Streaming%20and%20Batch%20execution%20strategies.

7️⃣ Feature: Modular Integration
https://github.com/ibrahmsql/Phobos/compare/main...feature/modular-integration?expand=1&title=feat:%20Integrate%20modular%20architecture&body=Export%20core%20and%20engines%20modules%20in%20lib.rs.

8️⃣ Docs: Advanced Features
https://github.com/ibrahmsql/Phobos/compare/main...docs/advanced-features?expand=1&title=docs:%20Add%20modular%20architecture%20documentation&body=Complete%20docs%20for%20traits,%20engines,%20fixtures.

EOF
