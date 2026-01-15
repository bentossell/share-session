// Cloudflare Pages Function to list private gists
// Token stored in CF dashboard: Settings > Environment variables > GITHUB_TOKEN

export async function onRequest(context) {
  const { env } = context;
  
  const headers = {
    'Content-Type': 'application/json',
    'Access-Control-Allow-Origin': '*',
  };

  if (!env.GITHUB_TOKEN) {
    return new Response(JSON.stringify({ error: 'GITHUB_TOKEN not configured' }), {
      status: 500,
      headers,
    });
  }

  try {
    const res = await fetch('https://api.github.com/gists?per_page=100', {
      headers: {
        'Authorization': `token ${env.GITHUB_TOKEN}`,
        'User-Agent': 'sessions-bentossell',
        'Accept': 'application/vnd.github.v3+json',
      },
    });

    if (!res.ok) {
      throw new Error(`GitHub API error: ${res.status}`);
    }

    const gists = await res.json();
    
    // Filter to session gists (have both .html and .jsonl)
    const sessionGists = gists.filter(g => {
      const files = Object.keys(g.files);
      return files.some(f => f.endsWith('.html')) && 
             files.some(f => f.endsWith('.jsonl'));
    });

    // Return minimal data
    const result = sessionGists.map(g => ({
      id: g.id,
      description: g.description || 'Untitled Session',
      created_at: g.created_at,
      files: Object.keys(g.files).length,
    }));

    return new Response(JSON.stringify(result), { headers });
  } catch (err) {
    return new Response(JSON.stringify({ error: err.message }), {
      status: 500,
      headers,
    });
  }
}
