import React, { useEffect, useMemo, useRef, useState } from 'react';
import axios from 'axios';
import { Bar, Line, Pie } from 'react-chartjs-2';

const normalizeApiBase = (raw) => {
  const value = raw == null ? '' : String(raw).trim();
  if (!value) return '';
  const noTrailingSlash = value.endsWith('/') ? value.slice(0, -1) : value;
  if (noTrailingSlash.endsWith('/api')) return noTrailingSlash;
  if (noTrailingSlash.startsWith('http://') || noTrailingSlash.startsWith('https://')) return `${noTrailingSlash}/api`;
  return '';
};

const getApiBaseUrl = () => {
  const fromEnv = normalizeApiBase(import.meta?.env?.VITE_API_BASE);
  if (fromEnv) return fromEnv;

  const params = new URLSearchParams(window.location.search);
  const fromQuery = normalizeApiBase(params.get('apiBase') || params.get('api'));
  if (fromQuery) {
    try {
      window.localStorage.setItem('APDS_API_BASE', fromQuery);
    } catch {
    }
    return fromQuery;
  }

  try {
    const fromStorage = normalizeApiBase(window.localStorage.getItem('APDS_API_BASE'));
    if (fromStorage) return fromStorage;
  } catch {
  }

  return `http://${window.location.hostname}:8080/api`;
};

const apiBaseUrl = getApiBaseUrl();

const api = axios.create({
  baseURL: apiBaseUrl,
  timeout: 10000,
});

const isDemoModeForced = (() => {
  try {
    return new URLSearchParams(window.location.search).get('demo') === '1';
  } catch {
    return false;
  }
})();

const buildDemoDataset = () => {
  const now = Date.now();
  const mk = (id, sourceIp, requestMethod, requestPath, attackType, riskScore, status, reason, mlProb) => ({
    id,
    sourceIp,
    requestMethod,
    requestPath,
    attackType,
    riskScore,
    status,
    suspicious: status !== 'NORMAL',
    reason,
    mlIntrusionProbability: mlProb,
    mlIntrusionPredicted: mlProb >= 0.5,
    timestamp: new Date(now - id * 3500).toISOString(),
  });

  const demoLogs = [
    mk(1, '192.168.1.10', 'GET', '/home', 'NONE', 0, 'NORMAL', null, 0.02),
    mk(2, '10.0.0.666', 'POST', '/api/login', 'RATE_LIMIT', 45, 'SUSPICIOUS', 'High request rate (>5 requests/10s)', 0.62),
    mk(3, '172.16.0.7', 'GET', "/products?q=' OR 1=1 --", 'SQL_INJECTION', 95, 'BLOCKED', 'SQL injection signature', 0.92),
    mk(4, '172.16.1.4', 'GET', '/search?q=<script>alert(1)</script>', 'XSS', 75, 'SUSPICIOUS', 'XSS signature', 0.73),
    mk(5, '185.199.10.31', 'GET', '/wp-admin', 'SCANNER', 85, 'BLOCKED', 'Scanner user-agent signature; Sensitive endpoint probing', 0.81),
    mk(6, '172.31.20.3', 'GET', '/download?file=../../../../etc/passwd', 'PATH_TRAVERSAL', 70, 'SUSPICIOUS', 'Path traversal signature', 0.66),
    mk(7, '172.31.30.2', 'GET', '/ping?host=8.8.8.8;cat%20/etc/passwd', 'COMMAND_INJECTION', 98, 'BLOCKED', 'Command injection signature', 0.94),
    mk(8, '172.31.40.9', 'GET', '/fetch?url=http://169.254.169.254/latest/meta-data/', 'SSRF', 92, 'BLOCKED', 'SSRF signature', 0.88),
    mk(9, '172.31.50.6', 'GET', '/index.php?page=php://filter/convert.base64-encode/resource=/etc/passwd', 'LFI', 88, 'BLOCKED', 'Local file inclusion signature', 0.86),
    mk(10, '172.31.60.1', 'GET', '/redirect?next=https://evil.example', 'OPEN_REDIRECT', 35, 'SUSPICIOUS', 'Open redirect signature', 0.41),
  ];

  const breakdown = demoLogs.reduce((acc, l) => {
    const k = l.attackType || 'NONE';
    acc[k] = (acc[k] || 0) + 1;
    return acc;
  }, {});

  const suspicious = demoLogs.filter((l) => l.status === 'SUSPICIOUS' || l.status === 'BLOCKED').length;
  const blocked = demoLogs.filter((l) => l.status === 'BLOCKED').length;
  const normal = demoLogs.filter((l) => l.status === 'NORMAL').length;

  return {
    stats: {
      suspicious,
      normal,
      blocked,
      active_blocks: blocked,
      attack_type_breakdown: breakdown,
      recent_flagged: demoLogs.filter((l) => l.status !== 'NORMAL').slice(0, 10),
    },
    blocks: demoLogs
      .filter((l) => l.status === 'BLOCKED')
      .map((l, idx) => ({
        id: idx + 1,
        sourceIp: l.sourceIp,
        blockedUntil: new Date(now + 5 * 60 * 1000).toISOString(),
        reason: l.reason || '',
      })),
    logs: demoLogs.slice().reverse(),
  };
};

const Dashboard = () => {
  const [stats, setStats] = useState({
    suspicious: 0,
    normal: 0,
    blocked: 0,
    active_blocks: 0,
    attack_type_breakdown: {},
    recent_flagged: [],
  });
  const [blocks, setBlocks] = useState([]);
  const [logs, setLogs] = useState([]);
  const [loading, setLoading] = useState(true);
  const [filters, setFilters] = useState({ limit: 200, ip: '', status: '', onlyFlagged: false });
  const [mlStatus, setMlStatus] = useState({ trained: false, samples: 0, trainedAt: null, lastHoldoutAccuracy: 0, modelType: null });
  const [mlModel, setMlModel] = useState('RANDOM_FOREST');
  const [mlTraining, setMlTraining] = useState(false);
  const [mlTrainError, setMlTrainError] = useState(null);
  const [liveMode, setLiveMode] = useState(true);
  const [autoScrollFeed, setAutoScrollFeed] = useState(true);
  const [newSinceId, setNewSinceId] = useState(0);
  const lastMaxIdRef = useRef(0);
  const feedRef = useRef(null);
  const [datasets, setDatasets] = useState([]);
  const [datasetProfile, setDatasetProfile] = useState('CICIDS2017');
  const [datasetFile, setDatasetFile] = useState(null);
  const [selectedDatasetId, setSelectedDatasetId] = useState('');
  const [datasetModel, setDatasetModel] = useState('RANDOM_FOREST');
  const [datasetMaxRows, setDatasetMaxRows] = useState(50000);
  const [datasetMlStatus, setDatasetMlStatus] = useState({ trained: false, training: false, samples: 0, trainedAt: null, lastHoldoutAccuracy: 0, modelType: null, datasetId: null, datasetProfile: null, lastError: null });
  const [shapExplanation, setShapExplanation] = useState(null);
  const [demoMode, setDemoMode] = useState(isDemoModeForced);

  const getStatus = (log) => {
    if (!log) return 'NORMAL';
    if (log.status) return log.status;
    return log.suspicious ? 'SUSPICIOUS' : 'NORMAL';
  };

  const getEventSeverity = (log) => {
    if (!log) return { label: 'LOW', color: '#36A2EB', bg: 'rgba(54,162,235,0.10)' };
    const status = getStatus(log);
    const score = typeof log?.riskScore === 'number' ? log.riskScore : 0;
    if (status === 'BLOCKED' || score >= 90) return { label: 'CRITICAL', color: '#f44336', bg: 'rgba(244,67,54,0.12)' };
    if (status === 'SUSPICIOUS' && score >= 70) return { label: 'HIGH', color: '#FF5722', bg: 'rgba(255,87,34,0.12)' };
    if (status === 'SUSPICIOUS') return { label: 'MEDIUM', color: '#FF9F40', bg: 'rgba(255,159,64,0.12)' };
    return { label: 'LOW', color: '#36A2EB', bg: 'rgba(54,162,235,0.10)' };
  };

  const fetchSummary = async () => {
    try {
      if (demoMode) {
        const demo = buildDemoDataset();
        setStats(demo.stats);
        setBlocks(demo.blocks);
        setMlStatus({ trained: true, samples: 2500, trainedAt: new Date().toISOString(), lastHoldoutAccuracy: 0.93, modelType: 'RANDOM_FOREST' });
        setDatasets([]);
        setDatasetMlStatus({ trained: true, training: false, samples: 50000, trainedAt: new Date().toISOString(), lastHoldoutAccuracy: 0.91, modelType: 'ENSEMBLE', datasetId: 'demo', datasetProfile: 'CICIDS2017', lastError: null });
        return;
      }
      const statsReq = api.get('/stats');
      const blocksReq = api.get('/blocks');
      const mlStatusReq = api.get('/ml/status');
      const datasetsReq = api.get('/datasets');
      const datasetMlStatusReq = api.get('/ml/dataset/status');

      const [statsRes, blocksRes, mlRes, datasetsRes, datasetMlRes] = await Promise.all([statsReq, blocksReq, mlStatusReq, datasetsReq, datasetMlStatusReq]);
      setStats(statsRes.data || { suspicious: 0, normal: 0, blocked: 0, active_blocks: 0, attack_type_breakdown: {}, recent_flagged: [] });
      setBlocks(blocksRes.data || []);
      setMlStatus(mlRes.data || { trained: false, samples: 0, trainedAt: null, lastHoldoutAccuracy: 0, modelType: null });
      const ds = Array.isArray(datasetsRes.data) ? datasetsRes.data : [];
      setDatasets(ds);
      setDatasetMlStatus(
        datasetMlRes.data || { trained: false, training: false, samples: 0, trainedAt: null, lastHoldoutAccuracy: 0, modelType: null, datasetId: null, datasetProfile: null, lastError: null }
      );
      if (!selectedDatasetId && ds.length > 0) {
        const last = [...ds].sort((a, b) => new Date(b?.uploadedAt || 0).getTime() - new Date(a?.uploadedAt || 0).getTime())[0];
        if (last?.id) setSelectedDatasetId(last.id);
      }
    } catch (error) {
      if (!demoMode) {
        setDemoMode(true);
        const demo = buildDemoDataset();
        setStats(demo.stats);
        setBlocks(demo.blocks);
        setMlStatus({ trained: true, samples: 2500, trainedAt: new Date().toISOString(), lastHoldoutAccuracy: 0.93, modelType: 'RANDOM_FOREST' });
        setDatasets([]);
        setDatasetMlStatus({ trained: true, training: false, samples: 50000, trainedAt: new Date().toISOString(), lastHoldoutAccuracy: 0.91, modelType: 'ENSEMBLE', datasetId: 'demo', datasetProfile: 'CICIDS2017', lastError: null });
        setLogs(demo.logs);
      }
    }
  };

  useEffect(() => {
    let mounted = true;
    const init = async () => {
      try {
        await fetchSummary();
      } catch (e) {
      }
      if (mounted) setLoading(false);
    };
    init();
    const summaryInterval = setInterval(fetchSummary, 5000);
    return () => {
      mounted = false;
      clearInterval(summaryInterval);
    };
  }, []);

  useEffect(() => {
    let logsMounted = true;
    const fetchLogsInterval = async () => {
      try {
        if (demoMode) {
          const demo = buildDemoDataset();
          if (!logsMounted) return;
          const items = Array.isArray(demo.logs) ? demo.logs : [];
          const maxId = items.reduce((m, l) => (typeof l?.id === 'number' ? Math.max(m, l.id) : m), 0);
          setNewSinceId(lastMaxIdRef.current);
          lastMaxIdRef.current = maxId;
          setLogs(items);
          return;
        }
        const logsRes = await api.get('/logs', {
          params: {
            limit: filters.limit,
            ip: filters.ip || undefined,
            status: filters.status || undefined,
            onlyFlagged: filters.onlyFlagged || undefined,
          },
        });

        if (!logsMounted) return;

        const items = Array.isArray(logsRes.data) ? logsRes.data : [];
        const maxId = items.reduce((m, l) => (typeof l?.id === 'number' ? Math.max(m, l.id) : m), 0);
        setNewSinceId(lastMaxIdRef.current);
        lastMaxIdRef.current = maxId;
        setLogs(items);
      } catch (error) {
        if (!demoMode) {
          setDemoMode(true);
          const demo = buildDemoDataset();
          setStats(demo.stats);
          setBlocks(demo.blocks);
          setMlStatus({ trained: true, samples: 2500, trainedAt: new Date().toISOString(), lastHoldoutAccuracy: 0.93, modelType: 'RANDOM_FOREST' });
          setDatasets([]);
          setDatasetMlStatus({ trained: true, training: false, samples: 50000, trainedAt: new Date().toISOString(), lastHoldoutAccuracy: 0.91, modelType: 'ENSEMBLE', datasetId: 'demo', datasetProfile: 'CICIDS2017', lastError: null });
          setLogs(demo.logs);
        }
      }
    };

    fetchLogsInterval();
    const intervalMs = liveMode ? 1000 : 5000;
    const logsInterval = setInterval(fetchLogsInterval, intervalMs);
    return () => {
      logsMounted = false;
      clearInterval(logsInterval);
    };
  }, [filters.limit, filters.ip, filters.status, filters.onlyFlagged, liveMode, demoMode]);

  const postLog = async (payload, refresh = true) => {
    try {
      await api.post('/log', payload);
      if (refresh) {
        await fetchSummary();
      }
    } catch (error) {
      console.error('Simulation error:', error);
    }
  };

  const simulateRequest = async () => {
    const ip = `192.168.1.${Math.floor(Math.random() * 10) + 1}`;
    const method = Math.random() > 0.7 ? 'POST' : 'GET';
    await postLog({ ip, method, path: '/home' });
  };

  const simulateRateAttack = async () => {
    const ip = '10.0.0.666';
    for (let i = 0; i < 12; i++) {
      await postLog({ ip, method: 'POST', path: '/api/login', attackType: 'RATE_LIMIT' }, false);
    }
    await fetchSummary();
  };

  const simulateSqlInjection = async () => {
    const ip = `172.16.0.${Math.floor(Math.random() * 10) + 1}`;
    await postLog({ ip, method: 'GET', path: "/products?q=' OR 1=1 --", attackType: 'SQLI' });
  };

  const simulateXss = async () => {
    const ip = `172.16.1.${Math.floor(Math.random() * 10) + 1}`;
    await postLog({ ip, method: 'GET', path: '/search?q=<script>alert(1)</script>', attackType: 'XSS' });
  };

  const simulateBruteForce = async () => {
    const ip = `10.10.0.${Math.floor(Math.random() * 10) + 1}`;
    for (let i = 0; i < 6; i++) {
      await postLog({ ip, method: 'POST', path: '/login', attackType: 'BRUTE_FORCE' }, false);
    }
    await fetchSummary();
  };

  const simulateScanner = async () => {
    const ip = `185.199.10.${Math.floor(Math.random() * 50) + 1}`;
    await postLog({ ip, method: 'GET', path: '/wp-admin', userAgent: 'sqlmap/1.7.10', attackType: 'SCANNER' });
  };

  const simulatePathTraversal = async () => {
    const ip = `172.31.20.${Math.floor(Math.random() * 10) + 1}`;
    await postLog({ ip, method: 'GET', path: '/download?file=../../../../etc/passwd', attackType: 'PATH_TRAVERSAL' });
  };

  const simulateCommandInjection = async () => {
    const ip = `172.31.30.${Math.floor(Math.random() * 10) + 1}`;
    await postLog({ ip, method: 'GET', path: '/ping?host=8.8.8.8;cat%20/etc/passwd', attackType: 'COMMAND_INJECTION' });
  };

  const simulateSsrf = async () => {
    const ip = `172.31.40.${Math.floor(Math.random() * 10) + 1}`;
    await postLog({ ip, method: 'GET', path: '/fetch?url=http://169.254.169.254/latest/meta-data/', attackType: 'SSRF' });
  };

  const simulateLfi = async () => {
    const ip = `172.31.50.${Math.floor(Math.random() * 10) + 1}`;
    await postLog({ ip, method: 'GET', path: '/index.php?page=php://filter/convert.base64-encode/resource=/etc/passwd', attackType: 'LFI' });
  };

  const simulateOpenRedirect = async () => {
    const ip = `172.31.60.${Math.floor(Math.random() * 10) + 1}`;
    await postLog({ ip, method: 'GET', path: '/redirect?next=https://evil.example', attackType: 'OPEN_REDIRECT' });
  };

  const simulateNoSqlInjection = async () => {
    const ip = `172.20.10.${Math.floor(Math.random() * 10) + 1}`;
    await postLog({ ip, method: 'GET', path: '/api/users?username[$ne]=&password[$ne]=', attackType: 'NOSQL_INJECTION' });
  };

  const simulateLdapInjection = async () => {
    const ip = `172.20.11.${Math.floor(Math.random() * 10) + 1}`;
    await postLog({ ip, method: 'GET', path: '/ldap?filter=*)(|(uid=*))', attackType: 'LDAP_INJECTION' });
  };

  const simulateCrlfInjection = async () => {
    const ip = `172.20.12.${Math.floor(Math.random() * 10) + 1}`;
    await postLog({ ip, method: 'GET', path: '/redirect?next=https://good.example%0d%0aSet-Cookie:%20pwned=1', attackType: 'CRLF_INJECTION' });
  };

  const simulateSsti = async () => {
    const ip = `172.20.13.${Math.floor(Math.random() * 10) + 1}`;
    await postLog({ ip, method: 'GET', path: '/welcome?name={{7*7}}', attackType: 'SSTI' });
  };

  const simulateRfi = async () => {
    const ip = `172.20.14.${Math.floor(Math.random() * 10) + 1}`;
    await postLog({ ip, method: 'GET', path: '/page?template=https://evil.example/shell.txt', attackType: 'RFI' });
  };

  const simulatePortScan = async () => {
    const ip = `203.0.113.${Math.floor(Math.random() * 50) + 1}`;
    const ports = [21, 22, 23, 80, 443, 3389];
    for (const port of ports) {
      await postLog({ ip, method: 'GET', path: `/probe?port=${port}`, attackType: 'PORT_SCAN' }, false);
    }
    await fetchSummary();
  };

  const unblockIp = async (ip) => {
    try {
      await api.post('/unblock', { ip });
      await fetchSummary();
    } catch (error) {
      console.error('Unblock error:', error);
    }
  };

  const trainMlModel = async () => {
    if (mlTraining) return;
    setMlTraining(true);
    setMlTrainError(null);
    try {
      const res = await api.post('/ml/train', null, { params: { model: mlModel } });
      const data = res?.data;
      if (data && data.trained === false && data.error) {
        setMlTrainError(String(data.error));
      } else if (data && data.trained === false && typeof data.samples === 'number' && data.samples < 30) {
        setMlTrainError(`Not enough logs to train (need >= 30). Current samples: ${data.samples}`);
      }
      await fetchSummary();
    } catch (error) {
      const msg = error?.response?.data?.error || error?.message || 'Training failed';
      console.error('ML train error:', error);
      setMlTrainError(String(msg));
    } finally {
      setMlTraining(false);
    }
  };

  const explainLog = async (logId) => {
    try {
      const res = await api.get('/ml/explain', { params: { logId, topK: 8 } });
      setShapExplanation(res.data || null);
    } catch (error) {
      console.error('Explain error:', error);
      setShapExplanation(null);
    }
  };

  const uploadDataset = async () => {
    if (!datasetFile) return;
    try {
      const form = new FormData();
      form.append('file', datasetFile);
      form.append('profile', datasetProfile);
      const res = await api.post('/datasets/upload', form, { headers: { 'Content-Type': 'multipart/form-data' } });
      if (res?.data?.id) setSelectedDatasetId(res.data.id);
      setDatasetFile(null);
      await fetchSummary();
    } catch (error) {
      console.error('Dataset upload error:', error);
    }
  };

  const trainDatasetModel = async () => {
    if (!selectedDatasetId) return;
    try {
      await api.post('/ml/dataset/train', null, { params: { datasetId: selectedDatasetId, model: datasetModel, maxRows: datasetMaxRows } });
      await fetchSummary();
    } catch (error) {
      console.error('Dataset train error:', error);
    }
  };

  const buildTrafficBuckets = useMemo(() => (windowSeconds, bucketSeconds) => {
    const nowMs = Date.now();
    const windowMs = windowSeconds * 1000;
    const bucketMs = bucketSeconds * 1000;
    const buckets = new Map();

    for (const log of logs) {
      if (!log?.timestamp) continue;
      const t = new Date(log.timestamp).getTime();
      if (!Number.isFinite(t)) continue;
      if (t < nowMs - windowMs) continue;

      const k = Math.floor(t / bucketMs) * bucketMs;
      const status = getStatus(log);
      const cur = buckets.get(k) || { NORMAL: 0, SUSPICIOUS: 0, BLOCKED: 0, TOTAL: 0 };
      cur.TOTAL += 1;
      if (status === 'BLOCKED') cur.BLOCKED += 1;
      else if (status === 'SUSPICIOUS') cur.SUSPICIOUS += 1;
      else cur.NORMAL += 1;
      buckets.set(k, cur);
    }

    const keys = Array.from(buckets.keys()).sort((a, b) => a - b);
    const labels = keys.map((k) =>
      new Date(k).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })
    );
    const values = keys.map((k) => buckets.get(k));
    return { labels, values };
  }, [logs]);

  const trafficByStatusChartData = useMemo(() => {
    const { labels, values } = buildTrafficBuckets(120, 5);
    return {
      labels,
      datasets: [
        { label: 'Normal', data: values.map((v) => v.NORMAL), borderColor: '#36A2EB', tension: 0.15, fill: false },
        { label: 'Suspicious', data: values.map((v) => v.SUSPICIOUS), borderColor: '#FF9F40', tension: 0.15, fill: false },
        { label: 'Blocked', data: values.map((v) => v.BLOCKED), borderColor: '#FF6384', tension: 0.15, fill: false },
      ],
    };
  }, [logs, buildTrafficBuckets]);

  const trafficTotalChartData = useMemo(() => {
    const { labels, values } = buildTrafficBuckets(120, 5);
    return {
      labels,
      datasets: [
        { label: 'Total', data: values.map((v) => v.TOTAL), borderColor: '#7E57C2', tension: 0.15, fill: false },
      ],
    };
  }, [logs, buildTrafficBuckets]);

  const suspiciousOnlyCount = Math.max((stats?.suspicious ?? 0) - (stats?.blocked ?? 0), 0);

  const pieChartData = {
    labels: ['Normal', 'Suspicious', 'Blocked'],
    datasets: [
      {
        data: [stats.normal, suspiciousOnlyCount, stats.blocked],
        backgroundColor: ['#36A2EB', '#FF9F40', '#FF6384'],
        hoverBackgroundColor: ['#36A2EB', '#FF9F40', '#FF6384'],
      },
    ],
  };

  const attackTypeEntries = Object.entries(stats.attack_type_breakdown || {}).sort((a, b) => (b[1] || 0) - (a[1] || 0));
  const topAttackTypes = attackTypeEntries.slice(0, 8);
  const barChartData = {
    labels: topAttackTypes.map(([k]) => k),
    datasets: [
      {
        label: 'Events',
        data: topAttackTypes.map(([, v]) => v),
        backgroundColor: '#7E57C2',
      },
    ],
  };

  const theme = {
    bg: '#05070f',
    bg2: '#070a16',
    surface: 'rgba(16, 24, 39, 0.86)',
    surface2: 'rgba(15, 23, 42, 0.92)',
    border: 'rgba(255, 255, 255, 0.10)',
    text: '#E5E7EB',
    muted: 'rgba(229, 231, 235, 0.72)',
  };

  const cardStyle = {
    background: theme.surface,
    padding: '14px',
    borderRadius: '8px',
    border: `1px solid ${theme.border}`,
    boxShadow: '0 10px 30px rgba(0,0,0,0.55)',
    backdropFilter: 'blur(10px)',
    transition: 'transform 140ms ease, box-shadow 140ms ease, border-color 140ms ease',
  };

  const numberStyle = { fontSize: '1.6em', fontWeight: 'bold', marginTop: '6px' };
  const panelStyle = {
    background: theme.surface,
    border: `1px solid ${theme.border}`,
    borderRadius: '10px',
    boxShadow: '0 10px 30px rgba(0,0,0,0.55)',
    backdropFilter: 'blur(12px)',
  };
  const inputStyle = { padding: '10px', borderRadius: '6px', border: `1px solid ${theme.border}`, background: theme.surface2, color: theme.text, outline: 'none' };
  const selectStyle = { padding: '10px 12px', borderRadius: '4px', border: `1px solid ${theme.border}`, background: theme.surface2, color: theme.text, outline: 'none' };

  const totalEvents = (stats.normal || 0) + (stats.suspicious || 0);

  const last60s = useMemo(() => {
    const nowMs = Date.now();
    const items = (logs || []).filter((l) => l?.timestamp && nowMs - new Date(l.timestamp).getTime() <= 60000);
    const counts = { NORMAL: 0, SUSPICIOUS: 0, BLOCKED: 0, TOTAL: 0 };
    for (const log of items) {
      const status = getStatus(log);
      counts.TOTAL += 1;
      if (status === 'BLOCKED') counts.BLOCKED += 1;
      else if (status === 'SUSPICIOUS') counts.SUSPICIOUS += 1;
      else counts.NORMAL += 1;
    }
    return counts;
  }, [logs]);

  const overallSeverity = useMemo(() => {
    const total = Math.max(last60s.TOTAL, 1);
    const blockedRate = last60s.BLOCKED / total;
    const suspiciousRate = last60s.SUSPICIOUS / total;

    if (last60s.BLOCKED >= 1 || blockedRate >= 0.1) return { label: 'CRITICAL', color: '#f44336', bg: 'rgba(244,67,54,0.10)' };
    if (last60s.SUSPICIOUS >= 6 || suspiciousRate >= 0.35) return { label: 'HIGH', color: '#FF5722', bg: 'rgba(255,87,34,0.10)' };
    if (last60s.SUSPICIOUS >= 1) return { label: 'MEDIUM', color: '#FF9F40', bg: 'rgba(255,159,64,0.10)' };
    return { label: 'LOW', color: '#4CAF50', bg: 'rgba(76,175,80,0.10)' };
  }, [last60s]);

  const feedLogs = useMemo(() => {
    const items = Array.isArray(logs) ? [...logs] : [];
    items.sort((a, b) => new Date(a?.timestamp || 0).getTime() - new Date(b?.timestamp || 0).getTime());
    return items.slice(-60);
  }, [logs]);

  useEffect(() => {
    if (!autoScrollFeed) return;
    const el = feedRef.current;
    if (!el) return;
    el.scrollTop = el.scrollHeight;
  }, [feedLogs.length, autoScrollFeed]);

  return (
    <div
      style={{
        minHeight: '100vh',
        background: `radial-gradient(1200px 600px at 20% -10%, rgba(126,87,194,0.35), transparent 60%), radial-gradient(900px 500px at 90% 10%, rgba(0,150,136,0.25), transparent 60%), linear-gradient(180deg, ${theme.bg} 0%, ${theme.bg2} 100%)`,
        color: theme.text,
        padding: '22px 14px',
        position: 'relative',
        overflow: 'hidden',
      }}
    >
      <style>{`
        .apds-card:hover { transform: translateY(-2px); box-shadow: 0 14px 38px rgba(0,0,0,0.65); border-color: rgba(255,255,255,0.18); }
        .apds-panel { position: relative; }
        .apds-panel::before { content: ""; position: absolute; inset: 0; border-radius: 10px; padding: 1px; background: linear-gradient(135deg, rgba(126,87,194,0.35), rgba(0,150,136,0.25), rgba(255,255,255,0.08)); -webkit-mask: linear-gradient(#000 0 0) content-box, linear-gradient(#000 0 0); -webkit-mask-composite: xor; mask-composite: exclude; pointer-events: none; opacity: 0.55; }
        .apds-btn { transition: transform 120ms ease, filter 120ms ease, box-shadow 120ms ease; box-shadow: 0 10px 22px rgba(0,0,0,0.45); }
        .apds-btn:hover { transform: translateY(-1px); filter: brightness(1.06); box-shadow: 0 14px 30px rgba(0,0,0,0.55); }
        .apds-btn:disabled { transform: none; filter: none; box-shadow: none; }
        .apds-table tbody tr:hover { background: rgba(255,255,255,0.03); }
        @keyframes apdsFloat { 0%{ transform: translate3d(0,0,0) scale(1); } 50%{ transform: translate3d(0,-18px,0) scale(1.02); } 100%{ transform: translate3d(0,0,0) scale(1); } }
      `}</style>
      <div style={{ position: 'absolute', inset: '-120px', pointerEvents: 'none' }}>
        <div style={{ position: 'absolute', left: '6%', top: '10%', width: '520px', height: '520px', background: 'radial-gradient(circle at 30% 30%, rgba(126,87,194,0.55), transparent 55%)', filter: 'blur(18px)', opacity: 0.45, animation: 'apdsFloat 8s ease-in-out infinite' }} />
        <div style={{ position: 'absolute', right: '2%', top: '8%', width: '520px', height: '520px', background: 'radial-gradient(circle at 70% 30%, rgba(0,150,136,0.45), transparent 55%)', filter: 'blur(18px)', opacity: 0.40, animation: 'apdsFloat 9s ease-in-out infinite' }} />
      </div>
      <div style={{ maxWidth: '1200px', margin: '0 auto' }}>
      {loading && logs.length === 0 ? (
        <div style={{ textAlign: 'center', padding: '40px 0', color: theme.muted }}>Loading Dashboard...</div>
      ) : (
        <>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'baseline', flexWrap: 'wrap', gap: '10px', marginBottom: '14px' }}>
        <div>
          <div style={{ fontSize: '22px', fontWeight: 900, letterSpacing: '0.2px' }}>APDS Security Dashboard</div>
          <div style={{ marginTop: '4px', fontSize: '0.95em', color: theme.muted }}>Real-time detection • blocking • ML insights</div>
        </div>
        <div style={{ display: 'flex', gap: '10px', alignItems: 'center', flexWrap: 'wrap' }}>
          {demoMode ? (
            <div style={{ display: 'flex', gap: '8px', alignItems: 'center', padding: '8px 10px', borderRadius: '999px', border: `1px solid ${theme.border}`, background: 'rgba(255, 159, 64, 0.10)' }}>
              <div style={{ width: '8px', height: '8px', borderRadius: '999px', background: '#FF9F40', boxShadow: '0 0 14px rgba(255,159,64,0.30)' }} />
              <div style={{ fontSize: '0.9em', color: theme.muted }}>Demo mode (no backend)</div>
            </div>
          ) : null}
          <div style={{ display: 'flex', gap: '8px', alignItems: 'center', padding: '8px 10px', borderRadius: '999px', border: `1px solid ${theme.border}`, background: theme.surface2 }}>
            <div style={{ width: '8px', height: '8px', borderRadius: '999px', background: mlStatus?.trained ? '#4CAF50' : '#FF9F40', boxShadow: mlStatus?.trained ? '0 0 14px rgba(76,175,80,0.35)' : '0 0 14px rgba(255,159,64,0.30)' }} />
            <div style={{ fontSize: '0.9em', color: theme.muted }}>Live ML: {mlStatus?.trained ? 'Trained' : 'Not trained'}</div>
          </div>
          <div style={{ display: 'flex', gap: '8px', alignItems: 'center', padding: '8px 10px', borderRadius: '999px', border: `1px solid ${theme.border}`, background: theme.surface2 }}>
            <div style={{ width: '8px', height: '8px', borderRadius: '999px', background: datasetMlStatus?.training ? '#3F51B5' : datasetMlStatus?.trained ? '#4CAF50' : '#607D8B', boxShadow: datasetMlStatus?.training ? '0 0 14px rgba(63,81,181,0.35)' : datasetMlStatus?.trained ? '0 0 14px rgba(76,175,80,0.35)' : '0 0 14px rgba(96,125,139,0.25)' }} />
            <div style={{ fontSize: '0.9em', color: theme.muted }}>Dataset ML: {datasetMlStatus?.training ? 'Training' : datasetMlStatus?.trained ? 'Trained' : 'Idle'}</div>
          </div>
        </div>
      </div>
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(6, 1fr)', gap: '12px', marginBottom: '16px' }}>
        <div className="apds-card" style={cardStyle}>
          <div>Total Events</div>
          <div style={numberStyle}>{totalEvents}</div>
        </div>
        <div className="apds-card" style={cardStyle}>
          <div>Normal</div>
          <div style={numberStyle}>{stats.normal}</div>
        </div>
        <div className="apds-card" style={cardStyle}>
          <div>Suspicious</div>
          <div style={numberStyle}>{suspiciousOnlyCount}</div>
        </div>
        <div className="apds-card" style={cardStyle}>
          <div>Blocked</div>
          <div style={numberStyle}>{stats.blocked}</div>
        </div>
        <div className="apds-card" style={cardStyle}>
          <div>Active Blocks</div>
          <div style={numberStyle}>{stats.active_blocks}</div>
        </div>
        <div className="apds-card" style={{ ...cardStyle, background: overallSeverity.bg, borderLeft: `6px solid ${overallSeverity.color}` }}>
          <div>Severity (Last 60s)</div>
          <div style={{ ...numberStyle, color: overallSeverity.color }}>{overallSeverity.label}</div>
          <div style={{ marginTop: '6px', fontSize: '0.85em', color: theme.muted }}>
            Total {last60s.TOTAL} | Susp {last60s.SUSPICIOUS} | Block {last60s.BLOCKED}
          </div>
        </div>
      </div>

      <div className="apds-panel" style={{ marginBottom: '16px', padding: '15px', ...panelStyle }}>
        <h3 style={{ marginTop: 0 }}>Simulation Controls</h3>
        <div style={{ display: 'flex', gap: '10px', flexWrap: 'wrap' }}>
          <button className="apds-btn" onClick={simulateRequest} style={{ padding: '10px 16px', backgroundColor: '#4CAF50', color: 'white', border: 'none', borderRadius: '10px', cursor: 'pointer' }}>
            Simulate Normal Request
          </button>
          <button className="apds-btn" onClick={simulateRateAttack} style={{ padding: '10px 16px', backgroundColor: '#f44336', color: 'white', border: 'none', borderRadius: '10px', cursor: 'pointer' }}>
            Simulate Rate Attack
          </button>
          <button className="apds-btn" onClick={simulateSqlInjection} style={{ padding: '10px 16px', backgroundColor: '#7E57C2', color: 'white', border: 'none', borderRadius: '10px', cursor: 'pointer' }}>
            Simulate SQL Injection
          </button>
          <button className="apds-btn" onClick={simulateXss} style={{ padding: '10px 16px', backgroundColor: '#009688', color: 'white', border: 'none', borderRadius: '10px', cursor: 'pointer' }}>
            Simulate XSS
          </button>
          <button className="apds-btn" onClick={simulateBruteForce} style={{ padding: '10px 16px', backgroundColor: '#FF9F40', color: 'white', border: 'none', borderRadius: '10px', cursor: 'pointer' }}>
            Simulate Brute Force
          </button>
          <button className="apds-btn" onClick={simulateScanner} style={{ padding: '10px 16px', backgroundColor: '#6D4C41', color: 'white', border: 'none', borderRadius: '10px', cursor: 'pointer' }}>
            Simulate Scanner
          </button>
          <button className="apds-btn" onClick={simulatePathTraversal} style={{ padding: '10px 16px', backgroundColor: '#00838F', color: 'white', border: 'none', borderRadius: '10px', cursor: 'pointer' }}>
            Simulate Path Traversal
          </button>
          <button className="apds-btn" onClick={simulateCommandInjection} style={{ padding: '10px 16px', backgroundColor: '#5E35B1', color: 'white', border: 'none', borderRadius: '10px', cursor: 'pointer' }}>
            Simulate Command Injection
          </button>
          <button className="apds-btn" onClick={simulateSsrf} style={{ padding: '10px 16px', backgroundColor: '#C62828', color: 'white', border: 'none', borderRadius: '10px', cursor: 'pointer' }}>
            Simulate SSRF
          </button>
          <button className="apds-btn" onClick={simulateLfi} style={{ padding: '10px 16px', backgroundColor: '#2E7D32', color: 'white', border: 'none', borderRadius: '10px', cursor: 'pointer' }}>
            Simulate LFI
          </button>
          <button className="apds-btn" onClick={simulateOpenRedirect} style={{ padding: '10px 16px', backgroundColor: '#546E7A', color: 'white', border: 'none', borderRadius: '10px', cursor: 'pointer' }}>
            Simulate Open Redirect
          </button>
          <button className="apds-btn" onClick={simulateNoSqlInjection} style={{ padding: '10px 16px', backgroundColor: '#00897B', color: 'white', border: 'none', borderRadius: '10px', cursor: 'pointer' }}>
            Simulate NoSQLi
          </button>
          <button className="apds-btn" onClick={simulateLdapInjection} style={{ padding: '10px 16px', backgroundColor: '#8E24AA', color: 'white', border: 'none', borderRadius: '10px', cursor: 'pointer' }}>
            Simulate LDAPi
          </button>
          <button className="apds-btn" onClick={simulateCrlfInjection} style={{ padding: '10px 16px', backgroundColor: '#C0CA33', color: 'white', border: 'none', borderRadius: '10px', cursor: 'pointer' }}>
            Simulate CRLF
          </button>
          <button className="apds-btn" onClick={simulateSsti} style={{ padding: '10px 16px', backgroundColor: '#3949AB', color: 'white', border: 'none', borderRadius: '10px', cursor: 'pointer' }}>
            Simulate SSTI
          </button>
          <button className="apds-btn" onClick={simulateRfi} style={{ padding: '10px 16px', backgroundColor: '#D84315', color: 'white', border: 'none', borderRadius: '10px', cursor: 'pointer' }}>
            Simulate RFI
          </button>
          <button className="apds-btn" onClick={simulatePortScan} style={{ padding: '10px 16px', backgroundColor: '#283593', color: 'white', border: 'none', borderRadius: '10px', cursor: 'pointer' }}>
            Simulate Port Scan
          </button>
          <button className="apds-btn" onClick={() => fetchSummary()} style={{ padding: '10px 16px', backgroundColor: '#607D8B', color: 'white', border: 'none', borderRadius: '10px', cursor: 'pointer' }}>
            Refresh Now
          </button>
          <select
            value={mlModel}
            onChange={(e) => setMlModel(e.target.value)}
            style={selectStyle}
          >
            <option value="RANDOM_FOREST">Random Forest</option>
            <option value="ENSEMBLE">Ensemble</option>
            <option value="XGBOOST">XGBoost</option>
            <option value="HYBRID">Hybrid (Ensemble+XGB)</option>
          </select>
          <button
            className="apds-btn"
            onClick={trainMlModel}
            disabled={mlTraining}
            style={{
              padding: '10px 16px',
              backgroundColor: mlTraining ? '#9fa8da' : '#3F51B5',
              color: 'white',
              border: 'none',
              borderRadius: '10px',
              cursor: mlTraining ? 'not-allowed' : 'pointer',
            }}
          >
            Train ML
          </button>
        </div>
        <div style={{ marginTop: '10px', fontSize: '0.9em', color: theme.muted }}>
          ML Status: {mlStatus.trained ? 'Trained' : 'Not trained'} | Model: {mlStatus.modelType || 'N/A'} | Samples: {mlStatus.samples || 0} | Holdout Acc: {((mlStatus.lastHoldoutAccuracy || 0) * 100).toFixed(1)}%
        </div>
        {mlTraining ? <div style={{ marginTop: '8px', fontSize: '0.9em', color: theme.muted }}>Training...</div> : null}
        {mlTrainError ? <div style={{ marginTop: '8px', fontSize: '0.9em', color: '#b71c1c' }}>Train error: {mlTrainError}</div> : null}
      </div>

      <div className="apds-panel" style={{ marginBottom: '16px', padding: '15px', ...panelStyle }}>
        <h3 style={{ marginTop: 0 }}>Dataset Training (CIC IDS 2017)</h3>
        <div style={{ display: 'flex', gap: '10px', flexWrap: 'wrap', alignItems: 'center' }}>
          <select value={datasetProfile} onChange={(e) => setDatasetProfile(e.target.value)} style={selectStyle}>
            <option value="CICIDS2017">CIC IDS 2017</option>
          </select>
          <input type="file" accept=".csv,.txt" onChange={(e) => setDatasetFile(e.target.files?.[0] || null)} />
          <button className="apds-btn" onClick={uploadDataset} style={{ padding: '10px 16px', backgroundColor: '#009688', color: 'white', border: 'none', borderRadius: '10px', cursor: 'pointer' }}>
            Upload Dataset
          </button>
          <select value={selectedDatasetId} onChange={(e) => setSelectedDatasetId(e.target.value)} style={{ ...selectStyle, minWidth: '280px' }}>
            <option value="">Select dataset</option>
            {datasets
              .slice()
              .sort((a, b) => new Date(b?.uploadedAt || 0).getTime() - new Date(a?.uploadedAt || 0).getTime())
              .map((d) => (
                <option key={d.id} value={d.id}>
                  {d.profile} | {d.originalFileName} | rows={d.rowCount}
                </option>
              ))}
          </select>
          <select value={datasetModel} onChange={(e) => setDatasetModel(e.target.value)} style={selectStyle}>
            <option value="RANDOM_FOREST">Random Forest</option>
            <option value="ENSEMBLE">Ensemble</option>
          </select>
          <input
            type="number"
            value={datasetMaxRows}
            onChange={(e) => setDatasetMaxRows(Number(e.target.value))}
            style={{ width: '120px', ...inputStyle }}
            min={1000}
            step={1000}
          />
          <button
            className="apds-btn"
            onClick={trainDatasetModel}
            disabled={datasetMlStatus.training || !selectedDatasetId}
            style={{
              padding: '10px 16px',
              backgroundColor: datasetMlStatus.training || !selectedDatasetId ? '#9fa8da' : '#3F51B5',
              color: 'white',
              border: 'none',
              borderRadius: '10px',
              cursor: datasetMlStatus.training || !selectedDatasetId ? 'not-allowed' : 'pointer',
            }}
          >
            Train Dataset Model
          </button>
        </div>
        <div style={{ marginTop: '10px', fontSize: '0.9em', color: theme.muted }}>
          Dataset ML Status: {datasetMlStatus.training ? 'Training...' : datasetMlStatus.trained ? 'Trained' : 'Not trained'} | Profile: {datasetMlStatus.datasetProfile || 'N/A'} | Dataset: {datasetMlStatus.datasetId || 'N/A'} | Model: {datasetMlStatus.modelType || 'N/A'} | Samples: {datasetMlStatus.samples || 0} | Holdout Acc: {((datasetMlStatus.lastHoldoutAccuracy || 0) * 100).toFixed(1)}%
        </div>
        {!selectedDatasetId ? <div style={{ marginTop: '8px', fontSize: '0.9em', color: '#b71c1c' }}>Select a dataset from the dropdown before training.</div> : null}
        {datasetMlStatus.lastError ? (
          <div style={{ marginTop: '8px', fontSize: '0.9em', color: '#b71c1c' }}>Last error: {datasetMlStatus.lastError}</div>
        ) : null}
      </div>

      <div className="apds-panel" style={{ marginBottom: '16px', padding: '15px', ...panelStyle }}>
        <h3 style={{ marginTop: 0 }}>Filters</h3>
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr 1fr', gap: '12px', alignItems: 'end' }}>
          <div>
            <div style={{ marginBottom: '6px', color: theme.muted }}>IP contains</div>
            <input
              value={filters.ip}
              onChange={(e) => setFilters((f) => ({ ...f, ip: e.target.value }))}
              style={{ width: '100%', ...inputStyle }}
              placeholder="e.g. 10.0.0"
            />
          </div>
          <div>
            <div style={{ marginBottom: '6px', color: theme.muted }}>Status</div>
            <select
              value={filters.status}
              onChange={(e) => setFilters((f) => ({ ...f, status: e.target.value }))}
              style={{ width: '100%', ...inputStyle }}
            >
              <option value="">All</option>
              <option value="NORMAL">NORMAL</option>
              <option value="SUSPICIOUS">SUSPICIOUS</option>
              <option value="BLOCKED">BLOCKED</option>
            </select>
          </div>
          <div>
            <div style={{ marginBottom: '6px', color: theme.muted }}>Limit</div>
            <select
              value={filters.limit}
              onChange={(e) => setFilters((f) => ({ ...f, limit: Number(e.target.value) }))}
              style={{ width: '100%', ...inputStyle }}
            >
              <option value={50}>50</option>
              <option value={100}>100</option>
              <option value={200}>200</option>
            </select>
          </div>
          <label style={{ display: 'flex', gap: '8px', alignItems: 'center', padding: '10px 0' }}>
            <input
              type="checkbox"
              checked={filters.onlyFlagged}
              onChange={(e) => setFilters((f) => ({ ...f, onlyFlagged: e.target.checked }))}
            />
            Only flagged
          </label>
        </div>
        <div style={{ marginTop: '12px', display: 'flex', gap: '16px', alignItems: 'center', flexWrap: 'wrap', color: theme.muted }}>
          <label style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
            <input type="checkbox" checked={liveMode} onChange={(e) => setLiveMode(e.target.checked)} />
            Live mode (1s)
          </label>
          <label style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
            <input type="checkbox" checked={autoScrollFeed} onChange={(e) => setAutoScrollFeed(e.target.checked)} />
            Auto-scroll feed
          </label>
          <div style={{ fontSize: '0.9em', color: theme.muted }}>
            New highlights: {newSinceId > 0 ? `id > ${newSinceId}` : 'warming up'}
          </div>
        </div>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '20px', marginBottom: '20px' }}>
        <div style={{ padding: '20px', ...panelStyle }}>
          <h3 style={{ marginTop: 0 }}>Traffic (Last 2m)</h3>
          <div style={{ marginBottom: '14px' }}>
            <div style={{ marginBottom: '6px', color: theme.muted }}>By status (bucket: 5s)</div>
            <Line data={trafficByStatusChartData} />
          </div>
          <div>
            <div style={{ marginBottom: '6px', color: theme.muted }}>Total (bucket: 5s)</div>
            <Line data={trafficTotalChartData} />
          </div>
        </div>

        <div style={{ padding: '20px', ...panelStyle }}>
          <h3 style={{ marginTop: 0 }}>Activity Distribution</h3>
          <div style={{ height: '300px', display: 'flex', justifyContent: 'center' }}>
            <Pie data={pieChartData} />
          </div>
        </div>
      </div>

      <div style={{ padding: '20px', marginBottom: '20px', ...panelStyle }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'baseline', gap: '12px', flexWrap: 'wrap' }}>
          <h3 style={{ marginTop: 0, marginBottom: '10px' }}>Live Log Feed</h3>
          <div style={{ fontSize: '0.9em', color: theme.muted }}>
            Polling: {liveMode ? '1s' : '5s'} | Showing last {feedLogs.length}
          </div>
        </div>
        <div
          ref={feedRef}
          style={{
            height: '260px',
            overflow: 'auto',
            border: `1px solid ${theme.border}`,
            borderRadius: '8px',
            padding: '10px',
            fontFamily: 'ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace',
            fontSize: '12px',
            background: theme.surface2,
          }}
        >
          {feedLogs.length === 0 ? (
            <div style={{ color: theme.muted }}>No events yet.</div>
          ) : (
            feedLogs.map((log) => {
              const status = getStatus(log);
              const sev = getEventSeverity(log);
              const isNew = typeof log?.id === 'number' && log.id > newSinceId;
              return (
                <div
                  key={log.id}
                  style={{
                    display: 'grid',
                    gridTemplateColumns: '120px 120px 80px 120px 1fr',
                    gap: '10px',
                    padding: '8px 10px',
                    borderRadius: '6px',
                    marginBottom: '6px',
                    background: isNew ? sev.bg : theme.surface,
                    border: `1px solid ${isNew ? sev.color : theme.border}`,
                  }}
                >
                  <div style={{ color: theme.muted }}>{log.timestamp ? new Date(log.timestamp).toLocaleTimeString() : ''}</div>
                  <div style={{ fontWeight: 700 }}>{log.sourceIp}</div>
                  <div style={{ color: sev.color, fontWeight: 800 }}>{sev.label}</div>
                  <div style={{ color: status === 'BLOCKED' ? '#f44336' : status === 'SUSPICIOUS' ? '#FF9F40' : '#36A2EB', fontWeight: 800 }}>
                    {status}
                  </div>
                  <div style={{ color: theme.text }}>
                    {log.requestMethod || ''} {log.requestPath || ''} | {log.attackType || ''} | score={log.riskScore ?? 0} | ml={(Number(log.mlIntrusionProbability || 0) * 100).toFixed(1)}%
                  </div>
                </div>
              );
            })
          )}
        </div>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '20px', marginBottom: '20px' }}>
        <div style={{ padding: '20px', ...panelStyle }}>
          <h3 style={{ marginTop: 0 }}>Top Attack Types</h3>
          <Bar data={barChartData} />
        </div>

        <div style={{ padding: '20px', ...panelStyle }}>
          <h3 style={{ marginTop: 0 }}>Active Blocks</h3>
          <table className="apds-table" style={{ width: '100%', borderCollapse: 'collapse' }}>
            <thead>
              <tr style={{ borderBottom: `2px solid ${theme.border}`, textAlign: 'left' }}>
                <th style={{ padding: '12px' }}>IP</th>
                <th style={{ padding: '12px' }}>Blocked Until</th>
                <th style={{ padding: '12px' }}>Action</th>
              </tr>
            </thead>
            <tbody>
              {blocks && blocks.length > 0 ? (
                blocks.map((b) => (
                  <tr key={b.id || b.sourceIp} style={{ borderBottom: `1px solid ${theme.border}` }}>
                    <td style={{ padding: '12px', fontWeight: 'bold' }}>{b.sourceIp}</td>
                    <td style={{ padding: '12px' }}>{b.blockedUntil ? new Date(b.blockedUntil).toLocaleString() : ''}</td>
                    <td style={{ padding: '12px' }}>
                      <button className="apds-btn" onClick={() => unblockIp(b.sourceIp)} style={{ padding: '8px 12px', backgroundColor: '#607D8B', color: 'white', border: 'none', borderRadius: '10px', cursor: 'pointer' }}>
                        Unblock
                      </button>
                    </td>
                  </tr>
                ))
              ) : (
                <tr>
                  <td colSpan="3" style={{ padding: '20px', textAlign: 'center', color: theme.muted }}>
                    No active blocks.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      <div style={{ padding: '20px', ...panelStyle }}>
        <h3 style={{ marginTop: 0 }}>Recent Events</h3>
        {shapExplanation ? (
          <div style={{ marginBottom: '14px', padding: '12px', border: `1px solid ${theme.border}`, borderRadius: '8px', background: theme.surface2 }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', gap: '12px', flexWrap: 'wrap', alignItems: 'baseline' }}>
              <div style={{ fontWeight: 800 }}>SHAP Explanation (XGBoost)</div>
              <button className="apds-btn" onClick={() => setShapExplanation(null)} style={{ padding: '6px 10px', backgroundColor: '#607D8B', color: 'white', border: 'none', borderRadius: '10px', cursor: 'pointer' }}>
                Close
              </button>
            </div>
            <div style={{ marginTop: '6px', fontSize: '0.9em', color: theme.muted }}>
              Model: {shapExplanation.modelType || 'N/A'} | XGB Prob: {((Number(shapExplanation.xgbProbability || 0)) * 100).toFixed(1)}%
              {shapExplanation.combinedProbability != null ? ` | Hybrid Prob: ${(Number(shapExplanation.combinedProbability) * 100).toFixed(1)}%` : ''}
            </div>
            <table className="apds-table" style={{ width: '100%', borderCollapse: 'collapse', marginTop: '10px' }}>
              <thead>
                <tr style={{ borderBottom: `2px solid ${theme.border}`, textAlign: 'left' }}>
                  <th style={{ padding: '10px' }}>Feature</th>
                  <th style={{ padding: '10px' }}>Value</th>
                  <th style={{ padding: '10px' }}>Contribution</th>
                </tr>
              </thead>
              <tbody>
                {(Array.isArray(shapExplanation.topContributions) ? shapExplanation.topContributions : []).map((c) => (
                  <tr key={c.feature} style={{ borderBottom: `1px solid ${theme.border}` }}>
                    <td style={{ padding: '10px', fontWeight: 700 }}>{c.feature}</td>
                    <td style={{ padding: '10px' }}>{Number(c.value).toFixed(3)}</td>
                    <td style={{ padding: '10px', color: Number(c.contribution) >= 0 ? '#2E7D32' : '#C62828', fontWeight: 800 }}>{Number(c.contribution).toFixed(6)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : null}
        <table className="apds-table" style={{ width: '100%', borderCollapse: 'collapse' }}>
          <thead>
            <tr style={{ borderBottom: `2px solid ${theme.border}`, textAlign: 'left' }}>
              <th style={{ padding: '12px' }}>ID</th>
              <th style={{ padding: '12px' }}>IP</th>
              <th style={{ padding: '12px' }}>Method</th>
              <th style={{ padding: '12px' }}>Path</th>
              <th style={{ padding: '12px' }}>Type</th>
              <th style={{ padding: '12px' }}>Score</th>
              <th style={{ padding: '12px' }}>ML Prob</th>
              <th style={{ padding: '12px' }}>ML Pred</th>
              <th style={{ padding: '12px' }}>Reason</th>
              <th style={{ padding: '12px' }}>Status</th>
              <th style={{ padding: '12px' }}>Severity</th>
              <th style={{ padding: '12px' }}>Explain</th>
              <th style={{ padding: '12px' }}>Time</th>
            </tr>
          </thead>
          <tbody>
            {logs && logs.length > 0 ? (
              logs.map((log) => (
                <tr key={log.id} style={{ borderBottom: `1px solid ${theme.border}` }}>
                  <td style={{ padding: '12px' }}>{log.id}</td>
                  <td style={{ padding: '12px', fontWeight: 'bold' }}>{log.sourceIp}</td>
                  <td style={{ padding: '12px' }}>{log.requestMethod}</td>
                  <td style={{ padding: '12px' }}>{log.requestPath || ''}</td>
                  <td style={{ padding: '12px' }}>{log.attackType || ''}</td>
                  <td style={{ padding: '12px' }}>{log.riskScore ?? ''}</td>
                  <td style={{ padding: '12px' }}>{log.mlIntrusionProbability != null ? `${(Number(log.mlIntrusionProbability) * 100).toFixed(1)}%` : ''}</td>
                  <td style={{ padding: '12px' }}>{log.mlIntrusionPredicted ? 'INTRUSION' : 'OK'}</td>
                  <td style={{ padding: '12px' }}>{log.reason || ''}</td>
                  <td style={{ padding: '12px', fontWeight: 'bold', color: getStatus(log) === 'BLOCKED' ? '#f44336' : getStatus(log) === 'SUSPICIOUS' ? '#FF9F40' : '#36A2EB' }}>{getStatus(log)}</td>
                  <td style={{ padding: '12px', fontWeight: 800, color: getEventSeverity(log).color }}>{getEventSeverity(log).label}</td>
                  <td style={{ padding: '12px' }}>
                    <button
                      onClick={() => explainLog(log.id)}
                      disabled={!(mlStatus?.modelType === 'XGBOOST' || mlStatus?.modelType === 'HYBRID')}
                      style={{
                        padding: '6px 10px',
                        backgroundColor: mlStatus?.modelType === 'XGBOOST' || mlStatus?.modelType === 'HYBRID' ? '#009688' : '#BDBDBD',
                        color: 'white',
                        border: 'none',
                        borderRadius: '4px',
                        cursor: mlStatus?.modelType === 'XGBOOST' || mlStatus?.modelType === 'HYBRID' ? 'pointer' : 'not-allowed',
                      }}
                    >
                      Explain
                    </button>
                  </td>
                  <td style={{ padding: '12px' }}>{log.timestamp ? new Date(log.timestamp).toLocaleString() : ''}</td>
                </tr>
              ))
            ) : (
              <tr>
                <td colSpan="13" style={{ padding: '20px', textAlign: 'center', color: theme.muted }}>
                  No events yet.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
        </>
      )}
      </div>
    </div>
  );
};

export default Dashboard;
