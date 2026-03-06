// ===========================
// NEXUS-CYBER DASHBOARD JS
// ===========================

const socket = io();

// Stats elements
const elTotal = document.getElementById('total-queries');
const elSafe = document.getElementById('safe-queries');
const elDangerous = document.getElementById('dangerous-queries');
const elCritical = document.getElementById('critical-queries');
const elBlocked = document.getElementById('blocked-ips');

// Stream elements
const queriesTable = document.getElementById('queries-table');
const threatsList = document.getElementById('threats-list');
const connStatus = document.getElementById('connection-status');

let queriesCache = [];
const maxTableRows = 15;

// ===========================
// SOCKET.IO EVENTS
// ===========================

socket.on('connect', () => {
    console.log('✓ SocketIO: Connected');
    connStatus.textContent = '● Connected';
    connStatus.className = 'status-indicator connected';

    // Subscribe to events
    socket.emit('subscribe_queries');
    socket.emit('subscribe_incidents');
});

socket.on('disconnect', () => {
    console.log('✗ SocketIO: Disconnected');
    connStatus.textContent = '● Disconnected';
    connStatus.className = 'status-indicator disconnected';
});

socket.on('query_detected', (query) => {
    console.debug('Live Query:', query);
    updateQueriesTable(query);
    refreshStats();
});

socket.on('incident_detected', (incident) => {
    console.log('Live Alert:', incident);
    updateThreatsList(incident);
    refreshStats();
});

// ===========================
// UPDATE UI FUNCTIONS
// ===========================

function updateQueriesTable(query) {
    queriesCache.unshift(query);
    if (queriesCache.length > maxTableRows) queriesCache.pop();

    queriesTable.innerHTML = '';
    queriesCache.forEach(q => {
        const row = document.createElement('tr');
        const timeStr = new Date(q.timestamp).toLocaleTimeString();
        const riskClass = `risk-${q.risk_level.toLowerCase()}`;
        const confidence = q.confidence_score ? (q.confidence_score * 100).toFixed(1) + '%' : 'N/A';

        row.innerHTML = `
            <td>${timeStr}</td>
            <td><code>${q.source_ip}</code></td>
            <td><span class="${riskClass}">${q.risk_level}</span></td>
            <td>${q.action_taken}</td>
            <td>${confidence}</td>
        `;
        queriesTable.appendChild(row);
    });
}

function updateThreatsList(incident) {
    // Remove placeholder if exists
    if (threatsList.querySelector('p')) threatsList.innerHTML = '';

    const item = document.createElement('div');
    const isCritical = incident.severity === 'CRITICAL';
    item.className = `threat-item ${isCritical ? '' : 'high'}`;

    const timeStr = new Date(incident.detected_at).toLocaleString();

    item.innerHTML = `
        <div class="threat-info">
            <h4>${incident.incident_type}</h4>
            <p><strong>Source:</strong> ${incident.source_ip} | <strong>Time:</strong> ${timeStr}</p>
            <p>${incident.summary || 'Advanced database analysis in progress...'}</p>
        </div>
        <div style="text-align: right;">
            <span class="severity-badge severity-${incident.severity.toLowerCase()}">
                ${incident.severity}
            </span>
            <br>
            <a href="/admin/incident/${incident.id}" style="font-size: 0.75rem; color: #58a6ff; text-decoration: none; margin-top: 0.5rem; display: inline-block;">
                Details →
            </a>
        </div>
    `;

    threatsList.prepend(item);

    // Keep only last 5 alerts
    if (threatsList.children.length > 5) {
        threatsList.removeChild(threatsList.lastChild);
    }
}

// ===========================
// API & CHARTS
// ===========================

let threatsChart = null;
let threatTypeChart = null;

async function refreshStats() {
    try {
        const res = await fetch('/api/stats');
        const data = await res.json();

        if (data.error) return;

        // Update Cards
        elTotal.textContent = data.query_stats.total_queries || 0;
        elSafe.textContent = data.query_stats.safe_queries || 0;
        elDangerous.textContent = data.query_stats.dangerous_queries || 0;
        elCritical.textContent = data.query_stats.critical_queries || 0;
        elBlocked.textContent = data.blocked_ips_count || 0;

        // Update Charts
        updateCharts(data);
    } catch (err) {
        console.error('Stats refresh failed:', err);
    }
}

function updateCharts(data) {
    // Threats Chart
    if (data.threats_by_hour) {
        const labels = data.threats_by_hour.map(h => h.hour.split(' ')[1]).reverse();
        const counts = data.threats_by_hour.map(h => h.threat_count).reverse();

        if (threatsChart) {
            threatsChart.data.labels = labels;
            threatsChart.data.datasets[0].data = counts;
            threatsChart.update();
        } else {
            initThreatsChart(labels, counts);
        }
    }

    // Risk distribution chart (from stat counts)
    const riskData = [
        data.query_stats.safe_queries || 0,
        data.query_stats.dangerous_queries || 0,
        data.query_stats.critical_queries || 0
    ];

    if (threatTypeChart) {
        threatTypeChart.data.datasets[0].data = riskData;
        threatTypeChart.update();
    } else {
        initRiskChart(riskData);
    }
}

function initThreatsChart(labels, data) {
    const ctx = document.getElementById('threatsChart').getContext('2d');
    threatsChart = new Chart(ctx, {
        type: 'line',
        data: {
            labels: labels.length ? labels : ['00:00'],
            datasets: [{
                label: 'Threats Detected',
                data: data.length ? data : [0],
                borderColor: '#f85149',
                backgroundColor: 'rgba(248, 81, 73, 0.1)',
                borderWidth: 2,
                tension: 0.3,
                fill: true
            }]
        },
        options: chartOptions
    });
}

function initRiskChart(data) {
    const ctx = document.getElementById('threatTypeChart').getContext('2d');
    threatTypeChart = new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: ['Safe', 'Dangerous', 'Critical'],
            datasets: [{
                data: data,
                backgroundColor: ['#238636', '#d29922', '#f85149'],
                borderWidth: 0
            }]
        },
        options: {
            ...chartOptions,
            plugins: {
                legend: { position: 'right', labels: { color: '#8b949e' } }
            }
        }
    });
}

const chartOptions = {
    responsive: true,
    maintainAspectRatio: false,
    scales: {
        y: { beginAtZero: true, grid: { color: '#30363d' }, ticks: { color: '#8b949e' } },
        x: { grid: { display: false }, ticks: { color: '#8b949e' } }
    },
    plugins: {
        legend: { labels: { color: '#8b949e' } }
    }
};

// Initial load
document.addEventListener('DOMContentLoaded', () => {
    refreshStats();
    setInterval(refreshStats, 30000); // 30s auto-refresh fallback
});
