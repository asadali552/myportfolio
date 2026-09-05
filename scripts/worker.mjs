// Same-origin bridge keeps the existing authenticated backend usable on Sites.
const upstream = 'https://devworkbyasad.vercel.app';
const routes = /^\/api\/(login|info|skills|projects|articles|analytics|messages)(\/[^?#]*)?$/;
export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (!routes.test(url.pathname)) return env.ASSETS ? env.ASSETS.fetch(request) : new Response('Not found', {status:404});
    const headers = new Headers();
    for (const name of ['accept','content-type','authorization']) {
      if (request.headers.has(name)) headers.set(name, request.headers.get(name));
    }
    try {
      const response = await fetch(upstream + url.pathname.replace(/^\/api/, '') + url.search, {
        method:request.method, headers,
        body:['GET','HEAD'].includes(request.method) ? undefined : request.body,
        redirect:'manual', signal:AbortSignal.timeout(20000)
      });
      const outgoing = new Headers({'content-type':response.headers.get('content-type') || 'application/json','cache-control':'no-store'});
      return new Response(response.body, {status:response.status,headers:outgoing});
    } catch { return Response.json({error:'The portfolio service is temporarily unavailable.'},{status:502}); }
  }
};
