/**
 * Fetcher Orchestrator
 * Runs all breach source fetchers and persists results to the database.
 */

const { upsertBreach, logFetch } = require('../db');
const { fetchMaineAG, SOURCE: MAINE_SOURCE } = require('./maine-ag');
const { fetchCaliforniaAG, SOURCE: CA_SOURCE } = require('./california-ag');
const { seedDemoData } = require('./demo-seed');

// Only attorney general breach notification portals are active fetchers.
// HHS, NCUA, ITRC, and RSS feeds have been removed from the active registry.
const FETCHERS = [
  { name: MAINE_SOURCE, fn: fetchMaineAG },
  { name: CA_SOURCE, fn: fetchCaliforniaAG },
];

async function runFetcher(fetcher) {
  const startTime = Date.now();
  let recordsFound = 0;
  let recordsNew = 0;

  try {
    console.log(`[Fetcher] Starting ${fetcher.name}...`);
    const breaches = await fetcher.fn();
    recordsFound = breaches.length;

    for (const breach of breaches) {
      const { isNew } = upsertBreach(breach);
      if (isNew) recordsNew++;
    }

    const elapsed = ((Date.now() - startTime) / 1000).toFixed(1);
    console.log(`[Fetcher] ${fetcher.name}: ${recordsFound} found, ${recordsNew} new (${elapsed}s)`);
    logFetch(fetcher.name, recordsFound, recordsNew, 'success');

  } catch (err) {
    console.error(`[Fetcher] ${fetcher.name} FAILED:`, err.message);
    logFetch(fetcher.name, recordsFound, recordsNew, 'error', err.message);
  }

  return { recordsFound, recordsNew };
}

async function runAllFetchers() {
  console.log('[Fetcher] Running all fetchers...');
  const results = {};

  for (const fetcher of FETCHERS) {
    results[fetcher.name] = await runFetcher(fetcher);
  }

  const total = Object.values(results).reduce((a, b) => ({ recordsFound: a.recordsFound + b.recordsFound, recordsNew: a.recordsNew + b.recordsNew }), { recordsFound: 0, recordsNew: 0 });
  console.log(`[Fetcher] Complete. Total: ${total.recordsFound} found, ${total.recordsNew} new`);

  return results;
}

async function runFetcherByName(name) {
  const fetcher = FETCHERS.find(f => f.name.toLowerCase() === name.toLowerCase());
  if (!fetcher) throw new Error(`Unknown fetcher: ${name}`);
  return runFetcher(fetcher);
}

function getFetcherNames() {
  return FETCHERS.map(f => f.name);
}

module.exports = { runAllFetchers, runFetcherByName, getFetcherNames, seedDemoData };
