const MEDIAMTX_API_URL = process.env.MEDIAMTX_API_URL || 'http://localhost:9997';

async function getActivePaths() {
  try {
    const res = await fetch(`${MEDIAMTX_API_URL}/v3/paths/list`);
    if (!res.ok) return [];
    const data = await res.json();
    return data.items || [];
  } catch {
    return [];
  }
}

async function isStreamLive(key) {
  const paths = await getActivePaths();
  return paths.some(p => p.name === key && p.readers && p.readers.length > 0 || p.source);
}

async function getActiveStreamKeys() {
  const paths = await getActivePaths();
  return paths
    .filter(p => p.source)
    .map(p => p.name);
}

async function getReaderCounts() {
  const paths = await getActivePaths();
  const counts = {};
  for (const p of paths) {
    if (p.source) {
      counts[p.name] = (p.readers && p.readers.length) || 0;
    }
  }
  return counts;
}

module.exports = { getActivePaths, isStreamLive, getActiveStreamKeys, getReaderCounts };
