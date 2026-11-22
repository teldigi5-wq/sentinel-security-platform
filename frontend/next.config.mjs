/** @type {import('next').NextConfig} */
const isDev = process.env.NODE_ENV !== 'production'

// Next's dev server (webpack HMR + React Fast Refresh) evaluates its own
// chunks via eval() at runtime. A CSP without 'unsafe-eval' silently breaks
// that runtime in the browser: the page still paints (static HTML/CSS), but
// no client-side JS wiring — onChange, onSubmit, state updates — ever runs,
// which looks like a stuck/disabled form rather than a script error unless
// you check the console. Production must stay strict; only dev relaxes this.
const scriptSrc = isDev ? "'self' 'unsafe-inline' 'unsafe-eval'" : "'self' 'unsafe-inline'"

const nextConfig = {
  reactStrictMode: true,
  poweredByHeader: false,
  async headers() {
    return [{source: '/:path*', headers: [
      {key: 'X-Content-Type-Options', value: 'nosniff'},
      {key: 'Referrer-Policy', value: 'no-referrer'},
      {key: 'X-Frame-Options', value: 'DENY'},
      {key: 'Permissions-Policy', value: 'camera=(), microphone=(), geolocation=()'},
      {key: 'Content-Security-Policy', value: `default-src 'self'; script-src ${scriptSrc}; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self' http://localhost:8000 http://127.0.0.1:8000; object-src 'none'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'`}
    ]}]
  }
}
export default nextConfig
