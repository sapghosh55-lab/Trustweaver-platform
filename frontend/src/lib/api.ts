/**
 * API client configuration for TrustWeaver platform.
 * Dynamically resolves the backend URL from the environment (e.g. live Render deployment),
 * falling back to local development server if not set.
 */

export const apiUrl = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000';

export const API_BASE_URL = apiUrl;

export async function postScan(url: string) {
  const response = await fetch(`${apiUrl}/scan`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ url }),
  });

  if (!response.ok) {
    throw new Error(`Scan server returned status ${response.status}`);
  }

  return response.json();
}

export async function getRecentScans(limit: number = 8) {
  const response = await fetch(`${apiUrl}/scans/recent?limit=${limit}`);
  if (!response.ok) {
    throw new Error(`Failed fetching recent scans: HTTP ${response.status}`);
  }
  return response.json();
}
