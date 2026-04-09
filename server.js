const express = require('express');
const cors = require('cors');
const cron = require('node-cron');
const path = require('path');
const { getBreaches, getBreach, upsertBreach, deleteBreach, getStats, getFetchLog } = require('./db');
const { runAllFetchers, runFetcherByName, getFetcherNames, seedDemoData } = require('./fetchers/index');

const app = express();
const PORT = process.env.PORT || 3000;

// ── Basic Auth ─────────────────────────────────────────────────────────────────
// Set APP_PASSWORD env var to enable. Skipped in local dev if not set.
const APP_PASSWORD = process.env.APP_PASSWORD;

if (APP_PASSWORD) {
  app.use((req, res, next) => {
    const auth = req.headers['authorization'];
    if (auth && auth.startsWith('Basic ')) {
      const decoded = Buffer.from(auth.slice(6), 'base64').toString();
      const [, pass] = decoded.split(':');
      if (pass === APP_PASSWORD) return next();
    }
    res.set('WWW-Authenticate', 'Basic realm="Credit Union Breach Tracker"');
    res.status(401).send('Unauthorized');
  });
}

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// ── Breach Routes ──────────────────────────────────────────────────────────────

app.get('/api/breaches', (req, res) => {
  try {
    const breaches = getBreaches(req.query);
    res.json({ success: true, data: breaches, count: breaches.length });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

app.get('/api/breaches/:id', (req, res) => {
  try {
    const breach = getBreach(parseInt(req.params.id));
    if (!breach) return res.status(404).json({ success: false, error: 'Not found' });
    res.json({ success: true, data: breach });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

app.post('/api/breaches', (req, res) => {
  try {
    const breach = { ...req.body, is_manual: 1, source: req.body.source || 'Manual Entry' };
    const { id, isNew } = upsertBreach(breach);
    res.status(isNew ? 201 : 200).json({ success: true, id, isNew });
  } catch (err) {
    res.status(400).json({ success: false, error: err.message });
  }
});

app.put('/api/breaches/:id', (req, res) => {
  try {
    const existing = getBreach(parseInt(req.params.id));
    if (!existing) return res.status(404).json({ success: false, error: 'Not found' });
    const updated = { ...existing, ...req.body, id: undefined };
    upsertBreach({ ...updated, external_id: existing.external_id });
    res.json({ success: true });
  } catch (err) {
    res.status(400).json({ success: false, error: err.message });
  }
});

app.delete('/api/breaches/:id', (req, res) => {
  try {
    deleteBreach(parseInt(req.params.id));
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// ── Stats ──────────────────────────────────────────────────────────────────────

app.get('/api/stats', (req, res) => {
  try {
    res.json({ success: true, data: getStats() });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// ── Fetch Controls ─────────────────────────────────────────────────────────────

app.post('/api/fetch', async (req, res) => {
  try {
    const { source } = req.body;
    let results;
    if (source) {
      results = await runFetcherByName(source);
    } else {
      results = await runAllFetchers();
    }
    res.json({ success: true, results });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

app.get('/api/fetchers', (req, res) => {
  res.json({ success: true, data: getFetcherNames() });
});

app.get('/api/fetch-log', (req, res) => {
  try {
    res.json({ success: true, data: getFetchLog() });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

app.post('/api/seed', async (req, res) => {
  try {
    const count = await seedDemoData();
    res.json({ success: true, seeded: count });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// ── CSV Export ─────────────────────────────────────────────────────────────────

app.get('/api/export/csv', (req, res) => {
  try {
    const breaches = getBreaches(req.query);
    const headers = [
      'id', 'organization', 'state', 'breach_date', 'notification_date',
      'breach_type', 'attack_vector', 'records_affected', 'data_types',
      'source', 'source_url', 'status', 'description'
    ];
    const csvRows = [headers.join(',')];
    for (const b of breaches) {
      const row = headers.map(h => {
        const val = b[h] ?? '';
        const str = String(val).replace(/"/g, '""');
        return str.includes(',') || str.includes('"') || str.includes('\n') ? `"${str}"` : str;
      });
      csvRows.push(row.join(','));
    }
    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', 'attachment; filename="credit-union-breaches.csv"');
    res.send(csvRows.join('\n'));
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// ── Scheduled Fetching (every 6 hours) ────────────────────────────────────────

cron.schedule('0 */6 * * *', () => {
  console.log('[Cron] Running scheduled fetch...');
  runAllFetchers().catch(err => console.error('[Cron] Error:', err.message));
});

// ── Start ──────────────────────────────────────────────────────────────────────

app.listen(PORT, async () => {
  console.log(`\n  Credit Union Breach Tracker`);
  console.log(`  ─────────────────────────────`);
  console.log(`  Server: http://localhost:${PORT}`);
  console.log(`  Seeding demo data...`);
  await seedDemoData();
  console.log(`  Ready. Auto-fetch runs every 6 hours.\n`);
});
