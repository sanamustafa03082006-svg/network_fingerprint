// ── State ──────────────────────────────────────────────
let mode = 'single';
let charts = {};

// ── Mode Toggle ────────────────────────────────────────
function setMode(m) {
    mode = m;
    document.getElementById('btn-single').classList.toggle('active', m === 'single');
    document.getElementById('btn-compare').classList.toggle('active', m === 'compare');
    document.getElementById('input-single').style.display  = m === 'single'  ? 'block' : 'none';
    document.getElementById('input-compare').style.display = m === 'compare' ? 'block' : 'none';
    document.getElementById('results').style.display = 'none';
}

// ── Validation ─────────────────────────────────────────
function validateURL(value, errId, inputId) {
    const pattern = /^https?:\/\/[a-zA-Z0-9\-._~:/?#[\]@!$&'()*+,;=%]+$/;
    const ok = pattern.test(value.trim());
    document.getElementById(errId).style.display = ok ? 'none' : 'block';
    document.getElementById(inputId).classList.toggle('error', !ok);
    return ok;
}

// ── Loader helpers ─────────────────────────────────────
const steps = [
    'Initializing packet sniffer...',
    'Resolving DNS for target URL...',
    'Capturing live network traffic...',
    'Extracting packet features...',
    'Generating fingerprint...',
    'Classifying behavior...',
];
let stepIndex = 0, stepTimer;

function startLoader() {
    document.getElementById('loader').style.display = 'block';
    document.getElementById('results').style.display = 'none';
    document.getElementById('analyzeBtn').disabled = true;
    stepIndex = 0;
    document.getElementById('loaderStep').textContent = steps[0];
    stepTimer = setInterval(() => {
        stepIndex = Math.min(stepIndex + 1, steps.length - 1);
        document.getElementById('loaderStep').textContent = steps[stepIndex];
    }, 1800);
}

function stopLoader() {
    clearInterval(stepTimer);
    document.getElementById('loader').style.display = 'none';
    document.getElementById('analyzeBtn').disabled = false;
}

// ── Chart helpers ──────────────────────────────────────
const COLORS = ['#00e5ff','#7c3aed','#ff6b35','#10b981','#f59e0b','#ec4899'];

function destroyChart(id) {
    if (charts[id]) { charts[id].destroy(); delete charts[id]; }
}

function makePie(canvasId, labels, values) {
    destroyChart(canvasId);
    charts[canvasId] = new Chart(document.getElementById(canvasId), {
        type: 'doughnut',
        data: {
            labels,
            datasets: [{ data: values, backgroundColor: COLORS, borderWidth: 0 }]
        },
        options: {
            plugins: {
                legend: { labels: { color: '#94a3b8', font: { family: 'Space Mono', size: 11 } } }
            },
            cutout: '55%'
        }
    });
}

function makeBar(canvasId, labels, values, label = 'Packets') {
    destroyChart(canvasId);
    charts[canvasId] = new Chart(document.getElementById(canvasId), {
        type: 'bar',
        data: {
            labels,
            datasets: [{
                label,
                data: values,
                backgroundColor: 'rgba(0,229,255,0.25)',
                borderColor: '#00e5ff',
                borderWidth: 1,
                borderRadius: 4
            }]
        },
        options: {
            plugins: { legend: { display: false } },
            scales: {
                x: { ticks: { color: '#64748b', font: { family: 'Space Mono', size: 10 } }, grid: { color: '#1e2d45' } },
                y: { ticks: { color: '#64748b', font: { family: 'Space Mono', size: 10 } }, grid: { color: '#1e2d45' } }
            }
        }
    });
}

function makeLine(canvasId, datasets) {
    destroyChart(canvasId);
    charts[canvasId] = new Chart(document.getElementById(canvasId), {
        type: 'line',
        data: { datasets },
        options: {
            parsing: false,
            plugins: {
                legend: { labels: { color: '#94a3b8', font: { family: 'Space Mono', size: 11 } } }
            },
            scales: {
                x: { type: 'linear', ticks: { color: '#64748b', font: { family: 'Space Mono', size: 10 } }, grid: { color: '#1e2d45' }, title: { display: true, text: 'Time (s)', color: '#64748b' } },
                y: { ticks: { color: '#64748b', font: { family: 'Space Mono', size: 10 } }, grid: { color: '#1e2d45' }, title: { display: true, text: 'Bytes', color: '#64748b' } }
            }
        }
    });
}

function timelinePoints(timeline) {
    const keys = Object.keys(timeline).map(Number).sort((a, b) => a - b);
    const base = keys[0] || 0;
    return keys.map(k => ({ x: k - base, y: timeline[k] }));
}

// ── Render single fingerprint ──────────────────────────
function renderSingle(data) {
    document.getElementById('single-results').style.display  = 'block';
    document.getElementById('compare-results').style.display = 'none';

    document.getElementById('fp-url').textContent      = data.site_url;
    document.getElementById('fp-behavior').textContent = `${data.behavior_label} · ${data.confidence}%`;
    document.getElementById('fp-packets').textContent  = data.total_packets.toLocaleString();
    document.getElementById('fp-bytes').textContent    = formatBytes(data.total_bytes);
    document.getElementById('fp-mean').textContent     = data.mean_packet_size + ' B';
    document.getElementById('fp-max').textContent      = data.max_packet_size + ' B';
    document.getElementById('fp-ips').textContent      = data.unique_ips.length;
    document.getElementById('fp-proto').textContent    = data.top_protocol || '—';

    // DNS
    const dnsSec  = document.getElementById('dns-section');
    const dnsList = document.getElementById('dns-list');
    if (data.dns_queries && data.dns_queries.length) {
        dnsSec.style.display = 'block';
        dnsList.innerHTML = data.dns_queries.slice(0, 12).map(q =>
            `<span class="dns-tag">${q}</span>`).join('');
    } else {
        dnsSec.style.display = 'none';
    }

    // Charts
    makePie('protocolChart', Object.keys(data.protocol_distribution), Object.values(data.protocol_distribution));
    makeBar('sizeChart', Object.keys(data.buckets), Object.values(data.buckets), 'Packets');
    makeLine('timelineChart', [{
        label: 'Bytes/sec',
        data: timelinePoints(data.timeline),
        borderColor: '#00e5ff',
        backgroundColor: 'rgba(0,229,255,0.08)',
        fill: true,
        tension: 0.4,
        pointRadius: 3
    }]);
}

// ── Render comparison ──────────────────────────────────
function renderCompare(a, b) {
    document.getElementById('single-results').style.display  = 'none';
    document.getElementById('compare-results').style.display = 'block';

    // Fill cards A and B
    fillCompareCard('a', a, b);
    fillCompareCard('b', b, a);

    // Charts
    makePie('protoChartA', Object.keys(a.protocol_distribution), Object.values(a.protocol_distribution));
    makePie('protoChartB', Object.keys(b.protocol_distribution), Object.values(b.protocol_distribution));

    makeLine('timelineCompare', [
        {
            label: new URL(a.site_url).hostname,
            data: timelinePoints(a.timeline),
            borderColor: '#00e5ff',
            backgroundColor: 'rgba(0,229,255,0.06)',
            fill: false, tension: 0.4, pointRadius: 3
        },
        {
            label: new URL(b.site_url).hostname,
            data: timelinePoints(b.timeline),
            borderColor: '#ff6b35',
            backgroundColor: 'rgba(255,107,53,0.06)',
            fill: false, tension: 0.4, pointRadius: 3
        }
    ]);
}

function fillCompareCard(side, mine, theirs) {
    document.getElementById(`fp-url-${side}`).textContent      = mine.site_url;
    document.getElementById(`fp-behavior-${side}`).textContent = `${mine.behavior_label} · ${mine.confidence}%`;

    const metrics = [
        { label: 'Total Packets', mine: mine.total_packets, theirs: theirs.total_packets, fmt: v => v.toLocaleString() },
        { label: 'Total Bytes',   mine: mine.total_bytes,   theirs: theirs.total_bytes,   fmt: formatBytes },
        { label: 'Mean Pkt Size', mine: mine.mean_packet_size, theirs: theirs.mean_packet_size, fmt: v => v + ' B' },
        { label: 'Unique IPs',    mine: mine.unique_ips.length, theirs: theirs.unique_ips.length, fmt: v => v }
    ];

    document.getElementById(`stats-${side}`).innerHTML = metrics.map(m => {
        const diff = m.mine > m.theirs ? `<span class="diff-badge diff-higher">▲ higher</span>`
                   : m.mine < m.theirs ? `<span class="diff-badge diff-lower">▼ lower</span>` : '';
        return `<div class="stat-box">
            <p class="stat-label">${m.label}</p>
            <p class="stat-value">${m.fmt(m.mine)}${diff}</p>
        </div>`;
    }).join('');
}

// ── Main analysis runner ───────────────────────────────
async function runAnalysis() {
    if (mode === 'single') {
        const url = document.getElementById('url1').value.trim();
        if (!validateURL(url, 'err1', 'url1')) return;

        startLoader();
        try {
            const res  = await fetch('/api/analyze', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ url })
            });
            const data = await res.json();
            stopLoader();

            if (data.error) { alert('Error: ' + data.error); return; }

            document.getElementById('results').style.display = 'block';
            renderSingle(data);
        } catch (e) {
            stopLoader();
            alert('Could not reach the server. Is Flask running?');
        }

    } else {
        const urlA = document.getElementById('url2a').value.trim();
        const urlB = document.getElementById('url2b').value.trim();
        const okA  = validateURL(urlA, 'err2a', 'url2a');
        const okB  = validateURL(urlB, 'err2b', 'url2b');
        if (!okA || !okB) return;

        startLoader();
        try {
            const res  = await fetch('/api/compare', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ url1: urlA, url2: urlB })
            });
            const data = await res.json();
            stopLoader();

            if (data.error) { alert('Error: ' + data.error); return; }

            document.getElementById('results').style.display = 'block';
            renderCompare(data.fingerprint1, data.fingerprint2);
        } catch (e) {
            stopLoader();
            alert('Could not reach the server. Is Flask running?');
        }
    }
}

// ── Utility ────────────────────────────────────────────
function formatBytes(bytes) {
    if (bytes < 1024) return bytes + ' B';
    if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
    return (bytes / (1024 * 1024)).toFixed(2) + ' MB';
}
