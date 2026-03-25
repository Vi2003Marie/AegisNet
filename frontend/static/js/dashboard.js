// Clock
function updateTime() {
    const now = new Date();
    document.getElementById('current-time').textContent = now.toLocaleString();
}
setInterval(updateTime, 1000);
updateTime();

// Traffic Chart
const ctx = document.getElementById('trafficChart').getContext('2d');
const trafficChart = new Chart(ctx, {
    type: 'line',
    data: {
        labels: [],
        datasets: [{
            label: 'Packets',
            data: [],
            borderColor: '#00d4ff',
            backgroundColor: 'rgba(0,212,255,0.05)',
            borderWidth: 2,
            fill: true,
            tension: 0.4
        }]
    },
    options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: { legend: { display: false } },
        scales: {
            x: { ticks: { color: '#7a8fa6' }, grid: { color: '#141e35' } },
            y: { ticks: { color: '#7a8fa6' }, grid: { color: '#141e35' } }
        }
    }
});

function updateChart(count) {
    const now = new Date().toLocaleTimeString();
    trafficChart.data.labels.push(now);
    trafficChart.data.datasets[0].data.push(count);
    if (trafficChart.data.labels.length > 15) {
        trafficChart.data.labels.shift();
        trafficChart.data.datasets[0].data.shift();
    }
    trafficChart.update();
}

// Fetch Stats
function fetchStats() {
    fetch('/api/stats')
        .then(r => r.json())
        .then(data => {
            document.getElementById('total-packets').textContent = data.total_packets;
            document.getElementById('total-devices').textContent = data.total_devices;
            document.getElementById('total-alerts').textContent = data.total_alerts;
            updateChart(data.total_packets);
        });
}

// Fetch Packets
function fetchPackets() {
    fetch('/api/packets')
        .then(r => r.json())
        .then(data => {
            const body = document.getElementById('packets-table');
            body.innerHTML = '';
            data.forEach(p => {
                body.innerHTML += `
                    <tr>
                        <td>${p.src_ip}</td>
                        <td>${p.dst_ip}</td>
                        <td>${p.protocol}</td>
                        <td>${p.packet_size} bytes</td>
                        <td>${p.timestamp ? new Date(p.timestamp).toLocaleTimeString() : 'N/A'}</td>
                    </tr>`;
            });
        });
}

// Fetch Alerts
function fetchAlerts() {
    fetch('/api/alerts')
        .then(r => r.json())
        .then(data => {
            const tbody = document.getElementById('alerts-table');
            tbody.innerHTML = '';
            if (data.length === 0) {
                tbody.innerHTML = '<tr><td colspan="4" style="text-align:center; color:#7a8fa6;">No alerts detected</td></tr>';
                return;
            }
            data.forEach(a => {
                const badge = a.severity === 'Critical' ? 'badge-high' : a.severity === 'High' ? 'badge-high' : a.severity === 'Medium' ? 'badge-medium' : 'badge-low';
                tbody.innerHTML += `
                    <tr>
                        <td>${a.src_ip}</td>
                        <td>${a.alert_type}</td>
                        <td>${a.description}</td>
                        <td><span class="${badge}">${a.severity}</span></td>
                        <td>${a.timestamp}</td>
                    </tr>`;
            });
        });
}

// Fetch Devices
function fetchDevices() {
    fetch('/api/devices')
        .then(r => r.json())
        .then(data => {
            const tbody = document.getElementById('devices-table');
            tbody.innerHTML = '';
            data.forEach(d => {
                tbody.innerHTML += `
                    <tr>
                        <td>${d.ip_address}</td>
                        <td>${d.mac_address}</td>
                        <td>
                            <span id="name-${d.ip_address.replace(/\./g, '_')}">${d.device_name || 'Unknown'}</span>
                            <button onclick="renameDevice('${d.ip_address}')"
                                style="background:none; border:none; color:#00d4ff; cursor:pointer; font-size:11px; margin-left:5px;">
                                <i class="fas fa-edit"></i>
                            </button>
                        </td>
                        <td>${d.first_seen ? new Date(d.first_seen).toLocaleTimeString() : 'N/A'}</td>
                        <td><span class="badge-active">${d.status}</span></td>
                    </tr>`;
            });
        });
}

function renameDevice(ip) {
    const newName = prompt('Enter a name for this device:');
    if (!newName) return;
    fetch('/rename_device', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ip: ip, name: newName })
    })
    .then(r => r.json())
    .then(data => {
        if (data.status === 'success') {
            const key = ip.replace(/\./g, '_');
            document.getElementById(`name-${key}`).textContent = newName;
        }
    });
}


// Fetch Blocked IPs
function fetchBlocked() {
    fetch('/api/blocked')
        .then(r => r.json())
        .then(data => {
            const tbody = document.getElementById('blocked-table');
            tbody.innerHTML = '';
            if (data.length === 0) {
                tbody.innerHTML = '<tr><td colspan="4" style="text-align:center; color:#7a8fa6;">No blocked IPs</td></tr>';
                return;
            }
            data.forEach(b => {
                tbody.innerHTML += `
                    <tr>
                        <td>${b.ip_address}</td>
                        <td>${b.reason}</td>
                        <td>${b.blocked_at}</td>
                        <td>
                            <button onclick="unblockIP('${b.ip_address}')"
                                style="background:#0f2a1a; color:#00cc66; border:1px solid #00cc66; padding:3px 12px; border-radius:8px; cursor:pointer; font-size:12px;">
                                <i class="fas fa-unlock"></i> Unblock
                            </button>
                        </td>
                    </tr>`;
            });
        });
}

function manualBlockIP() {
    const ip = document.getElementById('block-ip-input').value.trim();
    const reason = document.getElementById('block-reason-input').value.trim() || 'Manually blocked by admin';
    if (!ip) { alert('Please enter an IP address'); return; }
    fetch('/block_ip', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ip: ip, reason: reason })
    })
    .then(r => r.json())
    .then(data => {
        document.getElementById('block-ip-input').value = '';
        document.getElementById('block-reason-input').value = '';
        fetchBlocked();
    });
}

function unblockIP(ip) {
    fetch('/unblock_ip', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ip: ip })
    })
    .then(r => r.json())
    .then(() => fetchBlocked());
}

function fetchHealth() {
    fetch('/api/health')
        .then(r => r.json())
        .then(data => {
            if (!data.cpu_percent) return;

            // CPU
            document.getElementById('cpu-percent').textContent = data.cpu_percent + '%';
            document.getElementById('cpu-bar').style.width = data.cpu_percent + '%';
            document.getElementById('cpu-bar').style.background = data.cpu_percent > 80 ? '#ff4d4d' : '#00d4ff';

            // Memory
            document.getElementById('memory-percent').textContent = data.memory_percent + '%';
            document.getElementById('memory-bar').style.width = data.memory_percent + '%';
            document.getElementById('memory-bar').style.background = data.memory_percent > 95 ? '#ff4d4d' : '#00ff88';
            document.getElementById('memory-percent').style.color = data.memory_percent > 95 ? '#ff4d4d' : '#00ff88';
            document.getElementById('memory-detail').textContent = data.memory_used + ' GB / ' + data.memory_total + ' GB';

            // Disk
            document.getElementById('disk-percent').textContent = data.disk_percent + '%';
            document.getElementById('disk-bar').style.width = data.disk_percent + '%';
            document.getElementById('disk-bar').style.background = data.disk_percent > 90 ? '#ff4d4d' : '#ffaa00';
            document.getElementById('disk-detail').textContent = data.disk_used + ' GB / ' + data.disk_total + ' GB';

            // Network
            document.getElementById('bytes-sent').textContent = data.bytes_sent;
            document.getElementById('bytes-recv').textContent = data.bytes_recv;
        });
}

// Refresh every 5 seconds
function refreshAll() {
    fetchStats();
    fetchPackets();
    fetchAlerts();
    fetchDevices();
    fetchBlocked();
    fetchHealth();
}

refreshAll();
setInterval(refreshAll, 5000);