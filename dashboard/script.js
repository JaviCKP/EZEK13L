const THEME = {
    bg: "#030303",
    panel: "#0a0a0a",
    text: "#f0f0f0",
    gold: "#C5A059",
    goldDim: "rgba(197, 160, 89, 0.2)",
    muted: "#888888",
    critical: "#ff4b4b",
    telemetry: "#8F7B52"
};

const STATUS_COLORS = {
    "Critico": THEME.critical,
    "Ataque ML": "#ff9f43",
    "Confirmado": "#e8c47c",
    "Deriva ML": THEME.gold,
    "Senal experta": "#9ab56f",
    "Telemetria": THEME.telemetry,
    "Observado": THEME.muted,
};

function clearNode(node) {
    node.replaceChildren();
}

function appendText(parent, tag, text, className) {
    const node = document.createElement(tag);
    if (className) node.className = className;
    node.textContent = text ?? "-";
    parent.appendChild(node);
    return node;
}

function formatScore(value) {
    const parsed = Number.parseFloat(value);
    return Number.isFinite(parsed) ? parsed.toFixed(3) : "0.000";
}

function statusClassName(status) {
    return "status-" + String(status || "Observado").replaceAll(" ", "-");
}

async function fetchData() {
    try {
        const response = await fetch("/api/data?window_minutes=15&show_noise=false");
        if (!response.ok) throw new Error("Network error");
        return await response.json();
    } catch (e) {
        console.error("Error fetching data:", e);
        return null;
    }
}

function updatePipeline(pipeline) {
    const container = document.getElementById("pipeline-status");
    clearNode(container);
    for (const [key, active] of Object.entries(pipeline)) {
        const chip = document.createElement("div");
        chip.className = "status-chip";
        const dot = document.createElement("div");
        dot.className = `status-dot ${active ? "" : "inactive"}`;
        chip.appendChild(dot);
        chip.appendChild(document.createTextNode(key));
        container.appendChild(chip);
    }
}

function addMetric(container, label, value, sub) {
    const card = document.createElement("div");
    card.className = "metric-card";
    appendText(card, "div", label, "metric-label");
    appendText(card, "div", value, "metric-value");
    appendText(card, "div", sub, "metric-sub");
    container.appendChild(card);
}

function updateMetrics(metrics) {
    const container = document.getElementById("metrics-grid");
    clearNode(container);
    addMetric(container, "PCAPS LIVE", metrics.processed_pcaps, `${metrics.pending_pcaps} en cola | ${metrics.latest_pcap}`);
    addMetric(container, "SCOREADOS", metrics.total_scores, "Eventos analizados");
    addMetric(container, "DETECCIONES ML", metrics.ml_detections || 0, "Aprendidas y etiquetadas");
    addMetric(container, "ATAQUES ML", metrics.classifier_detections || 0, "Clasificador supervisado");
    addMetric(container, "DERIVA ML", metrics.anomalies, "Rareza sin etiqueta");
    addMetric(container, "EXPLICACIONES", metrics.expert_signals || 0, "No cuentan como ML");
    addMetric(container, "ALERTAS UTILES", metrics.useful_alerts, `${metrics.noise_alerts} ruido oculto`);
    addMetric(container, "BLOQUEADOS", metrics.blocked, `${metrics.failed_pcaps} PCAPs fallidos`);
}

function getPlotLayoutBase() {
    return {
        paper_bgcolor: "rgba(0,0,0,0)",
        plot_bgcolor: "rgba(0,0,0,0)",
        font: { color: THEME.text, family: "'Jura', sans-serif" },
        margin: { l: 40, r: 40, t: 20, b: 30 },
        legend: { orientation: "h", y: 1.1, x: 0, font: { color: THEME.muted } },
        xaxis: { showgrid: false, zeroline: false, color: THEME.muted },
        yaxis: { gridcolor: THEME.goldDim, zeroline: false, color: THEME.muted }
    };
}

function drawTimelineChart(data) {
    if (!window.Plotly) return;
    const { scores, meta } = data;
    if (!scores || scores.length === 0) {
        Plotly.react("timeline-chart", [], getPlotLayoutBase(), { displayModeBar: false });
        return;
    }

    const chronoScores = [...scores].sort((a, b) => new Date(a.dt) - new Date(b.dt));

    const traceRaw = {
        x: chronoScores.map(r => r.dt),
        y: chronoScores.map(r => r.raw_score ?? r.score),
        mode: "lines",
        name: "ML raw",
        line: { color: THEME.muted, width: 1 }
    };

    const traceHybrid = {
        x: chronoScores.map(r => r.dt),
        y: chronoScores.map(r => r.hybrid_score ?? r.score),
        mode: "lines",
        name: "Hibrido visible",
        line: { color: THEME.gold, width: 1.5, dash: "dot" }
    };

    const traceThreshold = {
        x: [chronoScores[0].dt, chronoScores[chronoScores.length - 1].dt],
        y: [meta.threshold, meta.threshold],
        mode: "lines",
        name: "Threshold",
        line: { color: THEME.critical, dash: "dash", width: 1 }
    };

    const anomalies = chronoScores.filter(r => r.is_ml_detection || r.is_ml_anomaly || r.is_anomaly);
    const traceAnomaly = {
        x: anomalies.map(r => r.dt),
        y: anomalies.map(r => r.hybrid_score ?? r.score),
        mode: "markers",
        name: "Deteccion ML",
        marker: { symbol: "diamond", size: 7, color: THEME.critical }
    };

    const layout = getPlotLayoutBase();
    layout.yaxis.title = "Score";
    layout.yaxis.range = [0, 1.05];

    Plotly.react("timeline-chart", [traceRaw, traceHybrid, traceThreshold, traceAnomaly], layout, { displayModeBar: false });
}

function drawStatusChart(scores) {
    if (!window.Plotly) return;
    if (!scores || scores.length === 0) {
        Plotly.react("status-chart", [], getPlotLayoutBase(), { displayModeBar: false });
        return;
    }

    const counts = {};
    scores.forEach(s => {
        counts[s.combined_status] = (counts[s.combined_status] || 0) + 1;
    });

    const order = ["Critico", "Ataque ML", "Confirmado", "Deriva ML", "Senal experta", "Telemetria", "Observado"];
    const yLabels = [];
    const xValues = [];
    const colors = [];

    order.forEach(status => {
        if (counts[status]) {
            yLabels.push(status);
            xValues.push(counts[status]);
            colors.push(STATUS_COLORS[status]);
        }
    });

    const trace = {
        x: xValues,
        y: yLabels,
        type: "bar",
        orientation: "h",
        marker: { color: colors },
        text: xValues,
        textposition: "outside",
        textfont: { color: THEME.text, family: "'JetBrains Mono', monospace" }
    };

    const layout = getPlotLayoutBase();
    layout.margin = { l: 80, r: 20, t: 10, b: 30 };
    layout.showlegend = false;

    Plotly.react("status-chart", [trace], layout, { displayModeBar: false });
}

function addCell(row, value, className) {
    const cell = document.createElement("td");
    if (className) cell.className = className;
    cell.textContent = value ?? "-";
    row.appendChild(cell);
    return cell;
}

function addFactorCell(row, factors, fallback) {
    const cell = document.createElement("td");
    cell.className = "factor-cell";
    const values = Array.isArray(factors) ? factors : [];
    if (!values.length) {
        cell.textContent = fallback || "-";
        row.appendChild(cell);
        return;
    }
    values.slice(0, 4).forEach(factor => {
        appendText(cell, "span", factor, "factor-chip");
    });
    row.appendChild(cell);
}

function updateMainTable(scores) {
    const tbody = document.querySelector("#events-table tbody");
    clearNode(tbody);
    const topScores = (scores || []).slice(0, 50);

    topScores.forEach(row => {
        const tr = document.createElement("tr");
        const time = row.dt ? new Date(row.dt).toLocaleTimeString() : "-";
        addCell(tr, time);
        addCell(tr, row.combined_status, statusClassName(row.combined_status));
        addCell(tr, row.src_ip || "-");
        addCell(tr, row.dst_ip || "-");
        addCell(tr, row.dst_port || "-");
        addCell(tr, row.ml_label || row.attack_prediction || "-", "attack-prediction");
        addCell(tr, formatScore(row.attack_confidence || 0), "attack-confidence");
        addCell(tr, formatScore(row.raw_score ?? row.score), "score-raw");
        addCell(tr, formatScore(row.hybrid_score ?? row.score), "score-final");
        addCell(tr, `+${formatScore(row.behavioral_boost)}`, "score-boost");
        addFactorCell(tr, row.behavioral_factors, row.factor_text);
        addCell(tr, row.suricata_label);
        addCell(tr, row.suricata_signature);
        tbody.appendChild(tr);
    });
}

function updateKeyValueTable(selector, values) {
    const tbody = document.querySelector(selector);
    clearNode(tbody);
    Object.entries(values || {}).forEach(([key, count]) => {
        const row = document.createElement("tr");
        addCell(row, key);
        addCell(row, count);
        tbody.appendChild(row);
    });
}

function updateTables(data) {
    updateMainTable(data.scores);
    updateKeyValueTable("#top-ips-table tbody", data.useful_ips);
    updateKeyValueTable("#top-sigs-table tbody", data.useful_signatures);
}

async function loop() {
    const data = await fetchData();
    if (data) {
        updatePipeline(data.pipeline);
        updateMetrics(data.metrics);
        drawTimelineChart(data);
        drawStatusChart(data.scores);
        updateTables(data);
    }
    setTimeout(loop, 2000);
}

loop();
