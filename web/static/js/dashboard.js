// Real-Time Dashboard Controller for AETHER IDS

document.addEventListener('DOMContentLoaded', () => {
    // Chart.js global configurations
    Chart.defaults.color = '#94a3b8'; // text-slate-400
    Chart.defaults.borderColor = 'rgba(255, 255, 255, 0.05)';

    // DOM Elements
    const statusDot = document.getElementById('status-dot');
    const statusText = document.getElementById('status-text');
    
    const statTotalPackets = document.getElementById('stat-total-packets');
    const statBandwidth = document.getElementById('stat-bandwidth');
    const statTotalSize = document.getElementById('stat-total-size');
    const statPps = document.getElementById('stat-pps');
    const statAlerts = document.getElementById('stat-alerts');
    
    const alertMetricCard = document.getElementById('alert-metric-card');
    const alertsStatusBadge = document.getElementById('alerts-status-badge');
    const alertsFeedContainer = document.getElementById('alerts-feed-container');
    const noAlertsPlaceholder = document.getElementById('no-alerts-placeholder');
    const packetsTableBody = document.getElementById('packets-table-body');
    const clearAlertsBtn = document.getElementById('clear-alerts');

    // State Variables
    let totalAlertsCount = 0;
    let alertsList = [];
    let processedPacketCount = 0;
    
    // Initialize Charts
    let throughputChart = initThroughputChart();
    let protocolChart = initProtocolChart();
    let portsChart = initPortsChart();

    // 1. Throughput Chart initialization (Line Chart)
    function initThroughputChart() {
        const ctx = document.getElementById('throughputChart').getContext('2d');
        
        // Linear gradient for throughput fill
        const gradient = ctx.createLinearGradient(0, 0, 0, 300);
        gradient.addColorStop(0, 'rgba(99, 102, 241, 0.3)');
        gradient.addColorStop(1, 'rgba(99, 102, 241, 0.0)');

        return new Chart(ctx, {
            type: 'line',
            data: {
                labels: [], // Timestamps
                datasets: [{
                    label: 'Packets / Sec (PPS)',
                    data: [],
                    borderColor: '#6366f1',
                    borderWidth: 2,
                    pointBackgroundColor: '#818cf8',
                    pointBorderColor: '#6366f1',
                    pointHoverRadius: 6,
                    fill: true,
                    backgroundColor: gradient,
                    tension: 0.4
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: { display: false },
                    tooltip: {
                        mode: 'index',
                        intersect: false,
                        backgroundColor: '#0f172a',
                        titleColor: '#fff',
                        bodyColor: '#cbd5e1',
                        borderWidth: 1,
                        borderColor: 'rgba(255, 255, 255, 0.1)'
                    }
                },
                scales: {
                    x: {
                        grid: { display: false },
                        ticks: { maxTicksLimit: 8 }
                    },
                    y: {
                        beginAtZero: true,
                        grid: { color: 'rgba(255, 255, 255, 0.05)' }
                    }
                }
            }
        });
    }

    // 2. Protocol Chart initialization (Doughnut Chart)
    function initProtocolChart() {
        const ctx = document.getElementById('protocolChart').getContext('2d');
        return new Chart(ctx, {
            type: 'doughnut',
            data: {
                labels: ['TCP', 'UDP', 'Other'],
                datasets: [{
                    data: [0, 0, 0],
                    backgroundColor: [
                        'rgba(59, 130, 246, 0.75)',  // Blue
                        'rgba(16, 185, 129, 0.75)',  // Emerald
                        'rgba(148, 163, 184, 0.5)'   // Slate
                    ],
                    borderColor: [
                        '#3b82f6',
                        '#10b981',
                        '#94a3b8'
                    ],
                    borderWidth: 1.5,
                    hoverOffset: 4
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: 'bottom',
                        labels: {
                            padding: 15,
                            usePointStyle: true,
                            font: { size: 11 }
                        }
                    }
                },
                cutout: '65%'
            }
        });
    }

    // 3. Target Ports Chart initialization (Horizontal Bar Chart)
    function initPortsChart() {
        const ctx = document.getElementById('portsChart').getContext('2d');
        return new Chart(ctx, {
            type: 'bar',
            data: {
                labels: [], // Target Ports
                datasets: [{
                    data: [], // Query Counts
                    backgroundColor: 'rgba(99, 102, 241, 0.65)',
                    borderColor: '#6366f1',
                    borderWidth: 1.5,
                    borderRadius: 4
                }]
            },
            options: {
                indexAxis: 'y',
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: { display: false }
                },
                scales: {
                    x: {
                        beginAtZero: true,
                        grid: { color: 'rgba(255, 255, 255, 0.05)' },
                        ticks: { precision: 0 }
                    },
                    y: {
                        grid: { display: false }
                    }
                }
            }
        });
    }

    // SSE Connection Setup
    let eventSource;
    
    function connectSSE() {
        eventSource = new EventSource('/stream');
        
        eventSource.onopen = () => {
            statusDot.className = 'w-2.5 h-2.5 bg-emerald-500 rounded-full animate-pulse';
            statusText.innerText = 'Connected';
            statusText.className = 'text-xs font-semibold text-emerald-400';
            console.log('SSE connection successfully opened');
        };

        eventSource.onerror = (err) => {
            statusDot.className = 'w-2.5 h-2.5 bg-red-500 rounded-full animate-ping';
            statusText.innerText = 'Reconnecting...';
            statusText.className = 'text-xs font-semibold text-red-400';
            console.error('SSE Connection failed. Re-attempting in 3s...', err);
            eventSource.close();
            setTimeout(connectSSE, 3000);
        };

        // Listen for standard system config packet
        eventSource.addEventListener('system', (e) => {
            const data = JSON.parse(e.data);
            console.log('System Status:', data);
        });

        // Listen for stats batches
        eventSource.addEventListener('stats', (e) => {
            const statsData = JSON.parse(e.data);
            updateDashboardStats(statsData);
        });

        // Listen for alerts instantly
        eventSource.addEventListener('alert', (e) => {
            const alertData = JSON.parse(e.data);
            handleIncomingAlert(alertData);
        });
    }

    // Update Dashboard Metrics and Charts
    function updateDashboardStats(data) {
        // Update upper level numerical text stats
        statTotalPackets.innerText = data.total_packets.toLocaleString();
        
        // Bandwidth KB/s to dynamic display
        statPps.innerHTML = `${data.current_pps} <span class="text-xs font-sans font-normal text-gray-400">pps</span>`;
        
        if (data.current_kbps >= 1024) {
            statBandwidth.innerHTML = `${(data.current_kbps / 1024).toFixed(2)} <span class="text-xs font-sans font-normal text-gray-400">Mbps</span>`;
        } else {
            statBandwidth.innerHTML = `${data.current_kbps.toFixed(2)} <span class="text-xs font-sans font-normal text-gray-400">Kbps</span>`;
        }
        
        // Total network bandwidth read
        const totalMB = data.total_bytes / (1024 * 1024);
        statTotalSize.innerText = `Total: ${totalMB.toFixed(2)} MB`;

        // Update 1: Throughput line chart
        const history = data.traffic_history;
        if (history && history.length > 0) {
            const labels = history.map(item => item.time);
            const ppsValues = history.map(item => item.pps);
            
            throughputChart.data.labels = labels;
            throughputChart.data.datasets[0].data = ppsValues;
            throughputChart.update('none'); // Update without animation triggers for performance
        }

        // Update 2: Protocol Breakdown chart
        const pDict = data.protocols;
        const tcpCount = pDict['TCP'] || 0;
        const udpCount = pDict['UDP'] || 0;
        const otherCount = Object.keys(pDict)
            .filter(k => k !== 'TCP' && k !== 'UDP')
            .reduce((sum, key) => sum + pDict[key], 0);
            
        protocolChart.data.datasets[0].data = [tcpCount, udpCount, otherCount];
        protocolChart.update();

        // Update 3: Top Ports Bar Chart
        const topPorts = data.top_ports; // List of [port, count]
        if (topPorts) {
            portsChart.data.labels = topPorts.map(p => `Port ${p[0]}`);
            portsChart.data.datasets[0].data = topPorts.map(p => p[1]);
            portsChart.update();
        }

        // Update 4: Packets Inspector Table
        updatePacketsTable(data.recent_packets);
    }

    // Format timestamps from float seconds to readable format
    function formatTime(timestamp) {
        const date = new Date(timestamp * 1000);
        return date.toTimeString().split(' ')[0] + '.' + String(date.getMilliseconds()).padStart(3, '0').slice(0, 2);
    }

    // Populate recent packets table
    function updatePacketsTable(packets) {
        if (!packets || packets.length === 0) return;
        
        // Optimize to avoid completely drawing the table if packet counter didn't change
        // But since we want live flashy rows, we update it.
        let htmlRows = '';
        
        packets.forEach(pkt => {
            const timeStr = formatTime(pkt.time);
            
            // Badge color based on protocol
            let protoClass = 'bg-gray-500/10 text-gray-400 border-gray-500/30';
            if (pkt.protocol === 'TCP') {
                protoClass = 'bg-blue-500/10 text-blue-400 border-blue-500/30';
            } else if (pkt.protocol === 'UDP') {
                protoClass = 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30';
            }

            const srcPortVal = pkt.src_port !== null ? pkt.src_port : '-';
            const destPortVal = pkt.dest_port !== null ? pkt.dest_port : '-';

            // Add flashing class for brand new rows to make dashboard feel alive
            const isNew = (processedPacketCount < pkt.time);
            const rowClass = isNew ? 'packet-row hover:bg-slate-900/40' : 'hover:bg-slate-900/40';

            htmlRows += `
                <tr class="${rowClass} border-b border-cyber-border/20 transition-colors">
                    <td class="py-2.5 px-4 text-gray-500 font-mono">${timeStr}</td>
                    <td class="py-2.5 px-4">
                        <span class="px-2 py-0.5 border text-[10px] font-semibold rounded font-tech ${protoClass}">${pkt.protocol}</span>
                    </td>
                    <td class="py-2.5 px-4 font-mono font-medium text-gray-300">${pkt.src_ip}</td>
                    <td class="py-2.5 px-4 font-mono font-medium text-gray-300">${pkt.dest_ip}</td>
                    <td class="py-2.5 px-4 font-mono text-center text-gray-400">${srcPortVal}</td>
                    <td class="py-2.5 px-4 font-mono text-center text-gray-400">${destPortVal}</td>
                    <td class="py-2.5 px-4 font-mono text-right text-indigo-300">${pkt.length}</td>
                    <td class="py-2.5 px-4 text-gray-400 truncate max-w-xs font-mono" title="${pkt.info}">${pkt.info}</td>
                </tr>
            `;
        });

        packetsTableBody.innerHTML = htmlRows;
        
        if (packets.length > 0) {
            processedPacketCount = packets[0].time;
        }
    }

    // Handle incoming Security Alert event from IDS
    function handleIncomingAlert(alert) {
        // Increment alerts counter
        totalAlertsCount++;
        statAlerts.innerText = totalAlertsCount;
        statAlerts.className = 'text-3xl font-bold font-tech text-red-500 animate-bounce';
        setTimeout(() => { statAlerts.className = 'text-3xl font-bold font-tech text-red-500'; }, 1000);

        // Put card into alarm mode
        alertMetricCard.className = 'glass-card p-5 relative overflow-hidden group border border-red-500/30 danger-glow-pulse transition-all duration-300';
        alertsStatusBadge.className = 'text-xs bg-red-950/40 text-red-400 px-2.5 py-0.5 rounded border border-red-500/40 font-semibold';
        alertsStatusBadge.innerText = 'BREACH DETECTED';

        // Add alert to local list
        alertsList.unshift(alert);
        if (alertsList.length > 20) {
            alertsList.pop();
        }

        // Hide placeholder if active
        if (noAlertsPlaceholder) {
            noAlertsPlaceholder.style.display = 'none';
        }

        // Build alert entry element
        const timeStr = formatTime(alert.time);
        const alertHtml = `
            <div class="alert-entry p-3 bg-red-950/15 border border-red-500/20 rounded-lg flex items-start justify-between gap-4">
                <div class="flex items-start gap-3">
                    <span class="flex-shrink-0 mt-0.5 p-1 bg-red-500/10 text-red-500 rounded border border-red-500/30">
                        <svg xmlns="http://www.w3.org/2000/svg" class="h-4 w-4" viewBox="0 0 20 20" fill="currentColor">
                            <path fill-rule="evenodd" d="M8.257 3.099c.765-1.36 2.722-1.36 3.486 0l5.58 9.92c.75 1.334-.213 2.98-1.742 2.98H4.42c-1.53 0-2.493-1.646-1.743-2.98l5.58-9.92zM11 13a1 1 0 11-2 0 1 1 0 012 0zm-1-8a1 1 0 00-1 1v3a1 1 0 002 0V6a1 1 0 00-1-1z" clip-rule="evenodd" />
                        </svg>
                    </span>
                    <div>
                        <h4 class="text-xs font-bold text-white font-tech uppercase tracking-wide flex items-center gap-1.5">
                            ${alert.type} 
                            <span class="text-[9px] px-1.5 py-0.2 bg-red-500/10 text-red-400 border border-red-500/30 rounded uppercase">${alert.severity}</span>
                        </h4>
                        <p class="text-[11px] text-red-300 mt-1 font-mono">${alert.details}</p>
                        <p class="text-[10px] text-gray-500 mt-0.5 font-mono">Source IP: <span class="text-gray-400 font-bold">${alert.src_ip}</span> &rarr; Target: <span class="text-gray-400">${alert.dest_ip}</span></p>
                    </div>
                </div>
                <span class="text-[10px] text-gray-500 font-mono whitespace-nowrap">${timeStr}</span>
            </div>
        `;

        // Render to container
        // If placeholder is still in the DOM or container is empty
        const placeholder = document.getElementById('no-alerts-placeholder');
        if (placeholder) {
            placeholder.remove();
        }

        alertsFeedContainer.insertAdjacentHTML('afterbegin', alertHtml);

        // Play alert sound (optional / disabled by default to avoid annoying user, but the glowing UI handles this visually)
    }

    // Clear alerts button logic
    clearAlertsBtn.addEventListener('click', () => {
        alertsFeedContainer.innerHTML = `
            <div id="no-alerts-placeholder" class="h-full flex flex-col items-center justify-center text-center py-12 text-gray-500">
                <svg xmlns="http://www.w3.org/2000/svg" class="h-12 w-12 text-gray-600 mb-3" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
                </svg>
                <p class="text-sm">No suspicious activities detected.</p>
                <p class="text-xs text-gray-600 mt-1">Ready and listening for anomalies...</p>
            </div>
        `;
        
        alertsList = [];
        totalAlertsCount = 0;
        statAlerts.innerText = '0';
        
        // Reset card borders
        alertMetricCard.className = 'glass-card p-5 relative overflow-hidden group hover:border-red-500/30 transition-all duration-300';
        alertsStatusBadge.className = 'text-xs bg-slate-800 text-gray-400 px-2.5 py-0.5 rounded border border-gray-700';
        alertsStatusBadge.innerText = 'SECURE';
    });

    // Run connection process
    connectSSE();
});
