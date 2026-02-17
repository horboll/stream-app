const fs = require('fs');
const path = require('path');

const NAMESPACE = process.env.JIBRI_NAMESPACE || 'jitsi-overlord';
const DEPLOYMENT_PATTERN = process.env.JIBRI_DEPLOYMENT_PATTERN || 'jitsi-shard-{shard}-jibri';
const SHARD_COUNT = parseInt(process.env.SHARD_COUNT || '1');
const MAX_REPLICAS = parseInt(process.env.JIBRI_MAX_REPLICAS || '3');
const MIN_REPLICAS = parseInt(process.env.JIBRI_MIN_REPLICAS || '1');
const SCALE_DOWN_GRACE_MS = 2 * 60 * 1000; // 2 minutes

let lastScaleDownRequest = null;
let pendingScaleDown = null;

function getK8sConfig() {
  const tokenPath = '/var/run/secrets/kubernetes.io/serviceaccount/token';
  const caPath = '/var/run/secrets/kubernetes.io/serviceaccount/ca.crt';

  try {
    const token = fs.readFileSync(tokenPath, 'utf8');
    const host = process.env.KUBERNETES_SERVICE_HOST;
    const port = process.env.KUBERNETES_SERVICE_PORT;
    return { token, host, port, caPath };
  } catch {
    return null;
  }
}

function getDeploymentNames() {
  const names = [];
  for (let i = 0; i < SHARD_COUNT; i++) {
    names.push(DEPLOYMENT_PATTERN.replace('{shard}', i));
  }
  return names;
}

async function getScale(deploymentName) {
  const k8s = getK8sConfig();
  if (!k8s) {
    console.warn('[jibri-scaler] Not running in cluster, skipping getScale');
    return 0;
  }

  const url = `https://${k8s.host}:${k8s.port}/apis/apps/v1/namespaces/${NAMESPACE}/deployments/${deploymentName}/scale`;
  const res = await fetch(url, {
    headers: { Authorization: `Bearer ${k8s.token}` },
  });

  if (!res.ok) {
    console.error(`[jibri-scaler] Failed to get scale for ${deploymentName}: ${res.status}`);
    return 0;
  }

  const data = await res.json();
  return data.spec.replicas || 0;
}

async function setScale(deploymentName, replicas) {
  const k8s = getK8sConfig();
  if (!k8s) {
    console.warn(`[jibri-scaler] Not running in cluster, would set ${deploymentName} to ${replicas}`);
    return;
  }

  const url = `https://${k8s.host}:${k8s.port}/apis/apps/v1/namespaces/${NAMESPACE}/deployments/${deploymentName}/scale`;
  const res = await fetch(url, {
    method: 'PATCH',
    headers: {
      Authorization: `Bearer ${k8s.token}`,
      'Content-Type': 'application/merge-patch+json',
    },
    body: JSON.stringify({ spec: { replicas } }),
  });

  if (!res.ok) {
    const body = await res.text();
    console.error(`[jibri-scaler] Failed to set scale for ${deploymentName}: ${res.status} ${body}`);
  } else {
    console.log(`[jibri-scaler] Scaled ${deploymentName} to ${replicas}`);
  }
}

async function reconcile(activeStreamCount) {
  const desired = Math.max(MIN_REPLICAS, Math.min(activeStreamCount, MAX_REPLICAS));
  const deployments = getDeploymentNames();

  for (const name of deployments) {
    const current = await getScale(name);

    if (desired > current) {
      // Scale up immediately
      if (pendingScaleDown) {
        clearTimeout(pendingScaleDown);
        pendingScaleDown = null;
      }
      await setScale(name, desired);
    } else if (desired < current) {
      // Scale down with grace period
      if (!pendingScaleDown) {
        console.log(`[jibri-scaler] Scheduling scale-down of ${name} from ${current} to ${desired} in ${SCALE_DOWN_GRACE_MS / 1000}s`);
        lastScaleDownRequest = Date.now();
        pendingScaleDown = setTimeout(async () => {
          const freshCount = await getScale(name);
          if (freshCount > desired) {
            await setScale(name, desired);
          }
          pendingScaleDown = null;
        }, SCALE_DOWN_GRACE_MS);
      }
    }
  }
}

module.exports = { reconcile, getScale, setScale, getDeploymentNames };
