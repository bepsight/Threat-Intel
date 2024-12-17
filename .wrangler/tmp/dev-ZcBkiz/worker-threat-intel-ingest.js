var __defProp = Object.defineProperty;
var __name = (target, value) => __defProp(target, "name", { value, configurable: true });
var __require = /* @__PURE__ */ ((x) => typeof require !== "undefined" ? require : typeof Proxy !== "undefined" ? new Proxy(x, {
  get: (a2, b2) => (typeof require !== "undefined" ? require : a2)[b2]
}) : x)(function(x) {
  if (typeof require !== "undefined")
    return require.apply(this, arguments);
  throw new Error('Dynamic require of "' + x + '" is not supported');
});

// .wrangler/tmp/bundle-hTwk8c/checked-fetch.js
var urls = /* @__PURE__ */ new Set();
function checkURL(request, init) {
  const url = request instanceof URL ? request : new URL(
    (typeof request === "string" ? new Request(request, init) : request).url
  );
  if (url.port && url.port !== "443" && url.protocol === "https:") {
    if (!urls.has(url.toString())) {
      urls.add(url.toString());
      console.warn(
        `WARNING: known issue with \`fetch()\` requests to custom HTTPS ports in published Workers:
 - ${url.toString()} - the custom port will be ignored when the Worker is published using the \`wrangler deploy\` command.
`
      );
    }
  }
}
__name(checkURL, "checkURL");
globalThis.fetch = new Proxy(globalThis.fetch, {
  apply(target, thisArg, argArray) {
    const [request, init] = argArray;
    checkURL(request, init);
    return Reflect.apply(target, thisArg, argArray);
  }
});

// node_modules/fauna/dist/browser/index.js
var er = Object.create;
var Et = Object.defineProperty;
var tr = Object.getOwnPropertyDescriptor;
var rr = Object.getOwnPropertyNames;
var nr = Object.getPrototypeOf;
var sr = Object.prototype.hasOwnProperty;
var nt = ((t) => typeof __require < "u" ? __require : typeof Proxy < "u" ? new Proxy(t, { get: (e, r) => (typeof __require < "u" ? __require : e)[r] }) : t)(function(t) {
  if (typeof __require < "u")
    return __require.apply(this, arguments);
  throw new Error('Dynamic require of "' + t + '" is not supported');
});
var or = /* @__PURE__ */ __name((t, e) => () => (e || t((e = { exports: {} }).exports, e), e.exports), "or");
var ar = /* @__PURE__ */ __name((t, e, r, s) => {
  if (e && typeof e == "object" || typeof e == "function")
    for (let n of rr(e))
      !sr.call(t, n) && n !== r && Et(t, n, { get: () => e[n], enumerable: !(s = tr(e, n)) || s.enumerable });
  return t;
}, "ar");
var ir = /* @__PURE__ */ __name((t, e, r) => (r = t != null ? er(nr(t)) : {}, ar(e || !t || !t.__esModule ? Et(r, "default", { value: t, enumerable: true }) : r, t)), "ir");
var st = /* @__PURE__ */ __name((t, e, r) => {
  if (!e.has(t))
    throw TypeError("Cannot " + r);
}, "st");
var a = /* @__PURE__ */ __name((t, e, r) => (st(t, e, "read from private field"), r ? r.call(t) : e.get(t)), "a");
var u = /* @__PURE__ */ __name((t, e, r) => {
  if (e.has(t))
    throw TypeError("Cannot add the same private member more than once");
  e instanceof WeakSet ? e.add(t) : e.set(t, r);
}, "u");
var f = /* @__PURE__ */ __name((t, e, r, s) => (st(t, e, "write to private field"), s ? s.call(t, r) : e.set(t, r), r), "f");
var ot = /* @__PURE__ */ __name((t, e, r, s) => ({ set _(n) {
  f(t, e, n, r);
}, get _() {
  return a(t, e, s);
} }), "ot");
var l = /* @__PURE__ */ __name((t, e, r) => (st(t, e, "access private method"), r), "l");
var Qt = or((Ve) => {
  "use strict";
  Ve.byteLength = lr;
  Ve.toByteArray = pr;
  Ve.fromByteArray = hr;
  var I = [], C = [], mr = typeof Uint8Array < "u" ? Uint8Array : Array, mt = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  for (te = 0, Pt = mt.length; te < Pt; ++te)
    I[te] = mt[te], C[mt.charCodeAt(te)] = te;
  var te, Pt;
  C["-".charCodeAt(0)] = 62;
  C["_".charCodeAt(0)] = 63;
  function Rt(t) {
    var e = t.length;
    if (e % 4 > 0)
      throw new Error("Invalid string. Length must be a multiple of 4");
    var r = t.indexOf("=");
    r === -1 && (r = e);
    var s = r === e ? 0 : 4 - r % 4;
    return [r, s];
  }
  __name(Rt, "Rt");
  function lr(t) {
    var e = Rt(t), r = e[0], s = e[1];
    return (r + s) * 3 / 4 - s;
  }
  __name(lr, "lr");
  function fr(t, e, r) {
    return (e + r) * 3 / 4 - r;
  }
  __name(fr, "fr");
  function pr(t) {
    var e, r = Rt(t), s = r[0], n = r[1], o = new mr(fr(t, s, n)), i = 0, d = n > 0 ? s - 4 : s, c;
    for (c = 0; c < d; c += 4)
      e = C[t.charCodeAt(c)] << 18 | C[t.charCodeAt(c + 1)] << 12 | C[t.charCodeAt(c + 2)] << 6 | C[t.charCodeAt(c + 3)], o[i++] = e >> 16 & 255, o[i++] = e >> 8 & 255, o[i++] = e & 255;
    return n === 2 && (e = C[t.charCodeAt(c)] << 2 | C[t.charCodeAt(c + 1)] >> 4, o[i++] = e & 255), n === 1 && (e = C[t.charCodeAt(c)] << 10 | C[t.charCodeAt(c + 1)] << 4 | C[t.charCodeAt(c + 2)] >> 2, o[i++] = e >> 8 & 255, o[i++] = e & 255), o;
  }
  __name(pr, "pr");
  function yr(t) {
    return I[t >> 18 & 63] + I[t >> 12 & 63] + I[t >> 6 & 63] + I[t & 63];
  }
  __name(yr, "yr");
  function gr(t, e, r) {
    for (var s, n = [], o = e; o < r; o += 3)
      s = (t[o] << 16 & 16711680) + (t[o + 1] << 8 & 65280) + (t[o + 2] & 255), n.push(yr(s));
    return n.join("");
  }
  __name(gr, "gr");
  function hr(t) {
    for (var e, r = t.length, s = r % 3, n = [], o = 16383, i = 0, d = r - s; i < d; i += o)
      n.push(gr(t, i, i + o > d ? d : i + o));
    return s === 1 ? (e = t[r - 1], n.push(I[e >> 2] + I[e << 4 & 63] + "==")) : s === 2 && (e = (t[r - 2] << 8) + t[r - 1], n.push(I[e >> 10] + I[e >> 4 & 63] + I[e << 2 & 63] + "=")), n.join("");
  }
  __name(hr, "hr");
});
var at = { default: new URL("https://db.fauna.com"), local: new URL("http://localhost:8443"), localhost: new URL("http://localhost:8443") };
var Q = /* @__PURE__ */ __name(class extends Error {
  constructor(...e) {
    super(...e);
  }
}, "Q");
var h = /* @__PURE__ */ __name(class extends Q {
  httpStatus;
  code;
  queryInfo;
  constraint_failures;
  constructor(e, r) {
    super(e.error.message), Error.captureStackTrace && Error.captureStackTrace(this, h), this.name = "ServiceError", this.code = e.error.code, this.httpStatus = r;
    let s = { txn_ts: e.txn_ts, summary: e.summary, query_tags: e.query_tags, stats: e.stats };
    this.queryInfo = s, this.constraint_failures = e.error.constraint_failures;
  }
}, "h");
var ae = /* @__PURE__ */ __name(class extends h {
  constructor(e, r) {
    super(e, r), Error.captureStackTrace && Error.captureStackTrace(this, ae), this.name = "QueryRuntimeError";
  }
}, "ae");
var G = /* @__PURE__ */ __name(class extends h {
  constructor(e, r) {
    super(e, r), Error.captureStackTrace && Error.captureStackTrace(this, G), this.name = "QueryCheckError";
  }
}, "G");
var Z = /* @__PURE__ */ __name(class extends h {
  constructor(e, r) {
    super(e, r), Error.captureStackTrace && Error.captureStackTrace(this, Z), this.name = "InvalidRequestError";
  }
}, "Z");
var ve = /* @__PURE__ */ __name(class extends h {
  constraint_failures;
  constructor(e, r) {
    super(e, r), Error.captureStackTrace && Error.captureStackTrace(this, G), this.name = "ConstraintFailureError", this.constraint_failures = e.error.constraint_failures;
  }
}, "ve");
var Fe = /* @__PURE__ */ __name(class extends h {
  abort;
  constructor(e, r) {
    super(e, r), Error.captureStackTrace && Error.captureStackTrace(this, G), this.name = "AbortError", this.abort = e.error.abort;
  }
}, "Fe");
var ie = /* @__PURE__ */ __name(class extends h {
  constructor(e, r) {
    super(e, r), Error.captureStackTrace && Error.captureStackTrace(this, ie), this.name = "AuthenticationError";
  }
}, "ie");
var ue = /* @__PURE__ */ __name(class extends h {
  constructor(e, r) {
    super(e, r), Error.captureStackTrace && Error.captureStackTrace(this, ue), this.name = "AuthorizationError";
  }
}, "ue");
var Oe = /* @__PURE__ */ __name(class extends h {
  constructor(e, r) {
    super(e, r), Error.captureStackTrace && Error.captureStackTrace(this, Z), this.name = "ContendedTransactionError";
  }
}, "Oe");
var V = /* @__PURE__ */ __name(class extends h {
  constructor(e, r) {
    super(e, r), Error.captureStackTrace && Error.captureStackTrace(this, V), this.name = "ThrottlingError";
  }
}, "V");
var ce = /* @__PURE__ */ __name(class extends h {
  stats;
  constructor(e, r) {
    super(e, r), Error.captureStackTrace && Error.captureStackTrace(this, ce), this.name = "QueryTimeoutError", this.stats = e.stats;
  }
}, "ce");
var de = /* @__PURE__ */ __name(class extends h {
  constructor(e, r) {
    super(e, r), Error.captureStackTrace && Error.captureStackTrace(this, de), this.name = "ServiceInternalError";
  }
}, "de");
var y = /* @__PURE__ */ __name(class extends Q {
  constructor(e, r) {
    super(e, r), Error.captureStackTrace && Error.captureStackTrace(this, y), this.name = "ClientError";
  }
}, "y");
var v = /* @__PURE__ */ __name(class extends Q {
  constructor(e, r) {
    super(e, r), Error.captureStackTrace && Error.captureStackTrace(this, v), this.name = "ClientClosedError";
  }
}, "v");
var w = /* @__PURE__ */ __name(class extends Q {
  constructor(e, r) {
    super(e, r), Error.captureStackTrace && Error.captureStackTrace(this, w), this.name = "NetworkError";
  }
}, "w");
var F = /* @__PURE__ */ __name(class extends Q {
  httpStatus;
  constructor(e) {
    super(e.message), Error.captureStackTrace && Error.captureStackTrace(this, F), this.name = "ProtocolError", this.httpStatus = e.httpStatus;
  }
}, "F");
var O = /* @__PURE__ */ __name((t, e) => {
  switch (t.error.code) {
    case "invalid_query":
      return new G(t, e);
    case "invalid_request":
      return new Z(t, e);
    case "abort":
      if (t.error.abort !== void 0)
        return new Fe(t, e);
      break;
    case "constraint_failure":
      if (t.error.constraint_failures !== void 0)
        return new ve(t, e);
      break;
    case "unauthorized":
      return new ie(t, e);
    case "forbidden":
      return new ue(t, e);
    case "contended_transaction":
      return new Oe(t, e);
    case "limit_exceeded":
      return new V(t, e);
    case "time_out":
      return new ce(t, e);
    case "internal_error":
      return new de(t, e);
  }
  return new ae(t, e);
}, "O");
var j = { QUERY: "/query/1", STREAM: "/stream/1", EVENT_FEED: "/feed/1" };
var be = /* @__PURE__ */ __name(class {
  #e;
  #t = j.QUERY;
  #r = j.STREAM;
  #n;
  constructor({ url: e, fetch_keepalive: r }) {
    this.#e = e, this.#n = r;
  }
  #s(e) {
    return new URL(e, this.#e).toString();
  }
  async request({ data: e, headers: r, method: s, client_timeout_ms: n, path: o = this.#t }) {
    let i = AbortSignal.timeout === void 0 ? (() => {
      let g = new AbortController(), x = g.signal;
      return setTimeout(() => g.abort(), n), x;
    })() : AbortSignal.timeout(n), d = await fetch(this.#s(o), { method: s, headers: { ...r, "Content-Type": "application/json" }, body: JSON.stringify(e), signal: i, keepalive: this.#n }).catch((g) => {
      throw new w("The network connection encountered a problem.", { cause: g });
    }), c = d.status, m = {};
    d.headers.forEach((g, x) => m[x] = g);
    let p = await d.text();
    return { status: c, body: p, headers: m };
  }
  stream({ data: e, headers: r, method: s, path: n = this.#r }) {
    let o = new Request(this.#s(n), { method: s, headers: { ...r, "Content-Type": "application/json" }, body: JSON.stringify(e), keepalive: this.#n }), i = new AbortController(), d = { signal: i.signal };
    async function* c() {
      let m = await fetch(o, d).catch((T) => {
        throw new w("The network connection encountered a problem.", { cause: T });
      }), p = m.status;
      if (!(p >= 200 && p < 400)) {
        let T = await m.json();
        throw O(T, p);
      }
      let g = m.body;
      if (!g)
        throw new Error("Response body is undefined.");
      let x = g.getReader();
      try {
        for await (let T of ur(x))
          yield T;
      } catch (T) {
        throw new w("The network connection encountered a problem while streaming events.", { cause: T });
      }
    }
    __name(c, "c");
    return { read: c(), close: () => {
      i.abort("Stream closed by the client.");
    } };
  }
  close() {
  }
}, "be");
async function* ur(t) {
  let e = new TextDecoder(), r = "";
  for await (let s of cr(t)) {
    let n = e.decode(s), o = (r + n).split(`
`);
    for (let i = 0; i < o.length - 1; i++)
      yield o[i].trim();
    r = o[o.length - 1];
  }
  r.trim() !== "" && (yield r);
}
__name(ur, "ur");
async function* cr(t) {
  let e = false;
  do {
    let r = await t.read();
    r.value !== void 0 && (yield r.value), e = r.done;
  } while (!e);
}
__name(cr, "cr");
var k;
try {
  k = nt("node:http2");
} catch {
  k = void 0;
}
var me;
var Se;
var xe;
var we;
var z;
var E;
var Ie;
var qe;
var Ne;
var _t;
var le;
var ke;
var Ee;
var it;
var De;
var Ct;
var He;
var At;
var K = /* @__PURE__ */ __name(class {
  constructor({ http2_session_idle_ms: e, url: r, http2_max_streams: s }) {
    u(this, le);
    u(this, Ee);
    u(this, De);
    u(this, He);
    u(this, Se, void 0);
    u(this, xe, void 0);
    u(this, we, void 0);
    u(this, z, 0);
    u(this, E, void 0);
    u(this, Ie, j.QUERY);
    u(this, qe, j.STREAM);
    if (k === void 0)
      throw new Error("Your platform does not support Node's http2 library");
    f(this, Se, e), f(this, xe, s), f(this, we, r), f(this, E, null);
  }
  static getClient(e) {
    var n;
    let r = l(n = K, Ne, _t).call(n, e);
    a(K, me).has(r) || a(K, me).set(r, new K(e));
    let s = a(K, me).get(r);
    return ot(s, z)._++, s;
  }
  async request(e) {
    let r = 0, s;
    do
      try {
        return await l(this, De, Ct).call(this, e);
      } catch (n) {
        if (n?.code !== "ERR_HTTP2_GOAWAY_SESSION")
          throw new w("The network connection encountered a problem.", { cause: n });
        s = n, r++;
      }
    while (r < 3);
    throw new w("The network connection encountered a problem.", { cause: s });
  }
  stream(e) {
    return l(this, He, At).call(this, e);
  }
  close() {
    this.isClosed() || (ot(this, z)._--, a(this, z) === 0 && a(this, E) && !a(this, E).closed && a(this, E).close());
  }
  isClosed() {
    return a(this, z) === 0;
  }
}, "K");
var ee = K;
me = /* @__PURE__ */ new WeakMap(), Se = /* @__PURE__ */ new WeakMap(), xe = /* @__PURE__ */ new WeakMap(), we = /* @__PURE__ */ new WeakMap(), z = /* @__PURE__ */ new WeakMap(), E = /* @__PURE__ */ new WeakMap(), Ie = /* @__PURE__ */ new WeakMap(), qe = /* @__PURE__ */ new WeakMap(), Ne = /* @__PURE__ */ new WeakSet(), _t = /* @__PURE__ */ __name(function({ http2_session_idle_ms: e, url: r }) {
  return `${r}|${e}`;
}, "_t"), le = /* @__PURE__ */ new WeakSet(), ke = /* @__PURE__ */ __name(function() {
  f(this, z, 0), a(this, E) && !a(this, E).closed && a(this, E).close();
}, "ke"), Ee = /* @__PURE__ */ new WeakSet(), it = /* @__PURE__ */ __name(function() {
  if (!a(this, E) || a(this, E).closed || a(this, E).destroyed) {
    let e = k.connect(a(this, we), { peerMaxConcurrentStreams: a(this, xe) }).once("error", () => l(this, le, ke).call(this)).once("goaway", () => l(this, le, ke).call(this));
    e.setTimeout(a(this, Se), () => {
      l(this, le, ke).call(this);
    }), f(this, E, e);
  }
  return a(this, E);
}, "it"), De = /* @__PURE__ */ new WeakSet(), Ct = /* @__PURE__ */ __name(function({ client_timeout_ms: e, data: r, headers: s, method: n, path: o = a(this, Ie) }) {
  return new Promise((i, d) => {
    let c, m = /* @__PURE__ */ __name((p) => {
      let g = Number(p[k.constants.HTTP2_HEADER_STATUS]), x = "";
      c.on("data", (T) => {
        x += T;
      }), c.on("end", () => {
        i({ status: g, body: x, headers: p });
      });
    }, "m");
    try {
      let p = { ...s, [k.constants.HTTP2_HEADER_PATH]: o, [k.constants.HTTP2_HEADER_METHOD]: n };
      c = l(this, Ee, it).call(this).request(p).setEncoding("utf8").on("error", (x) => {
        d(x);
      }).on("response", m), c.write(JSON.stringify(r), "utf8"), c.setTimeout(e, () => {
        c.destroy(new Error("Client timeout"));
      }), c.end();
    } catch (p) {
      d(p);
    }
  });
}, "Ct"), He = /* @__PURE__ */ new WeakSet(), At = /* @__PURE__ */ __name(function({ data: e, headers: r, method: s, path: n = a(this, qe) }) {
  let o, i, d = /* @__PURE__ */ __name(() => new Promise((T, oe) => {
    o = T, i = oe;
  }), "d"), c = d(), m, p = /* @__PURE__ */ __name((T) => {
    let oe = Number(T[k.constants.HTTP2_HEADER_STATUS]);
    if (oe >= 200 && oe < 400) {
      let $ = "";
      m.on("data", (R) => {
        let X = ($ + R).split(`
`);
        o(X.map((rt) => rt.trim()).slice(0, -1)), c = d(), $ = X[X.length - 1];
      }), m.on("end", () => {
        o([$]);
      });
    } else {
      let $ = "";
      m.on("data", (R) => {
        $ += R;
      }), m.on("end", () => {
        try {
          let R = JSON.parse($);
          i(O(R, oe));
        } catch (R) {
          i(new w("Could not process query failure.", { cause: R }));
        }
      });
    }
  }, "p"), g = this;
  async function* x() {
    var R;
    let T = { ...r, [k.constants.HTTP2_HEADER_PATH]: n, [k.constants.HTTP2_HEADER_METHOD]: s };
    m = l(R = g, Ee, it).call(R).request(T).setEncoding("utf8").on("error", (X) => {
      i(X);
    }).on("response", p);
    let $ = JSON.stringify(e);
    for (m.write($, "utf8"), m.end(); ; ) {
      let X = await c;
      for (let rt of X)
        yield rt;
    }
  }
  __name(x, "x");
  return { read: x(), close: () => {
    m && m.close();
  } };
}, "At"), u(ee, Ne), u(ee, me, /* @__PURE__ */ new Map());
var ut = /* @__PURE__ */ __name((t) => dr() ? ee.getClient(t) : new be(t), "ut");
var ct = /* @__PURE__ */ __name((t) => t instanceof Object && "body" in t && "headers" in t && "status" in t, "ct");
var dt = /* @__PURE__ */ __name((t) => "stream" in t && typeof t.stream == "function", "dt");
var dr = /* @__PURE__ */ __name(() => {
  if (typeof process < "u" && process && process.release?.name === "node")
    try {
      return nt("node:http2"), true;
    } catch {
      return false;
    }
  return false;
}, "dr");
var pt = ir(Qt());
var Tr = /(?:\d{4}|[\u2212-]\d{4,}|\+\d{5,})/;
var br = /(?:0[1-9]|1[0-2])/;
var Sr = /(?:0[1-9]|[12]\d|3[01])/;
var vt = /(?:[01][0-9]|2[0-3])/;
var _e = /(?:[0-5][0-9])/;
var xr = /(?:\.\d+)/;
var lt = new RegExp(`(${Tr.source}-(${br.source})-(${Sr.source}))`);
var wr = new RegExp(`(${vt.source}:${_e.source}:${_e.source}${xr.source}?)`);
var Er = new RegExp(`([zZ]|[+\u2212-]${vt.source}(?::?${_e.source}|:${_e.source}:${_e.source}))`);
var Ft = new RegExp(`^${lt.source}$`);
var Ot = new RegExp(`^${lt.source}`);
var kt = new RegExp(`^${lt.source}T${wr.source}${Er.source}$`);
var q = /* @__PURE__ */ __name(class {
  isoString;
  constructor(e) {
    this.isoString = e;
  }
  static from(e) {
    if (typeof e != "string")
      throw new TypeError(`Expected string but received ${typeof e}: ${e}`);
    if (kt.exec(e) === null)
      throw new RangeError(`(regex) Expected an ISO date string but received '${e}'`);
    return new q(e);
  }
  static fromDate(e) {
    return new q(e.toISOString());
  }
  toDate() {
    let e = new Date(this.isoString);
    if (e.toString() === "Invalid Date")
      throw new RangeError("Fauna Date could not be converted to Javascript Date");
    return e;
  }
  toString() {
    return `TimeStub("${this.isoString}")`;
  }
}, "q");
var N = /* @__PURE__ */ __name(class {
  dateString;
  constructor(e) {
    this.dateString = e;
  }
  static from(e) {
    if (typeof e != "string")
      throw new TypeError(`Expected string but received ${typeof e}: ${e}`);
    let r = Ft.exec(e);
    if (r === null)
      throw new RangeError(`Expected a plain date string but received '${e}'`);
    return new N(r[0]);
  }
  static fromDate(e) {
    let r = e.toISOString(), s = Ot.exec(r);
    if (s === null)
      throw new y(`Failed to parse date '${e}'`);
    return new N(s[0]);
  }
  toDate() {
    let e = /* @__PURE__ */ new Date(this.dateString + "T00:00:00Z");
    if (e.toString() === "Invalid Date")
      throw new RangeError("Fauna Date could not be converted to Javascript Date");
    return e;
  }
  toString() {
    return `DateStub("${this.dateString}")`;
  }
}, "N");
var M = /* @__PURE__ */ __name(class {
  coll;
  id;
  constructor({ coll: e, id: r }) {
    this.id = r, typeof e == "string" ? this.coll = new W(e) : this.coll = e;
  }
}, "M");
var fe = /* @__PURE__ */ __name(class extends M {
  ts;
  ttl;
  constructor(e) {
    let { coll: r, id: s, ts: n, ...o } = e;
    super({ coll: r, id: s }), this.ts = n, Object.assign(this, o);
  }
  toObject() {
    return { ...this };
  }
}, "fe");
var Y = /* @__PURE__ */ __name(class {
  coll;
  name;
  constructor({ coll: e, name: r }) {
    this.name = r, typeof e == "string" ? this.coll = new W(e) : this.coll = e;
  }
}, "Y");
var pe = /* @__PURE__ */ __name(class extends Y {
  ts;
  data;
  constructor(e) {
    let { coll: r, name: s, ts: n, data: o, ...i } = e;
    super({ coll: r, name: s }), this.ts = n, this.data = o || {}, Object.assign(this, i);
  }
  toObject() {
    return { ...this };
  }
}, "pe");
var W = /* @__PURE__ */ __name(class {
  name;
  constructor(e) {
    this.name = e;
  }
}, "W");
var re = /* @__PURE__ */ __name(class {
  ref;
  cause;
  constructor(e, r) {
    this.ref = e, this.cause = r;
  }
}, "re");
var D = /* @__PURE__ */ __name(class {
  data;
  after;
  constructor({ data: e, after: r }) {
    this.data = e, this.after = r;
  }
}, "D");
var L = /* @__PURE__ */ __name(class {
  after;
  constructor(e) {
    this.after = e;
  }
}, "L");
var U = /* @__PURE__ */ __name(class {
  #e;
  constructor(e, r, s) {
    if (s = s ?? {}, r instanceof Function)
      this.#e = Cr(e, r, s);
    else if (r instanceof D || r instanceof L)
      this.#e = It(e, r, s);
    else
      throw new TypeError(`Expected 'Page<T> | EmbeddedSet | (() => Promise<T | Page<T> | EmbeddedSet>)', but received ${JSON.stringify(r)}`);
  }
  static fromQuery(e, r, s) {
    return new U(e, async () => (await e.query(r, s)).data, s);
  }
  static fromPageable(e, r, s) {
    return new U(e, r, s);
  }
  flatten() {
    return new je(this);
  }
  async next() {
    return this.#e.next();
  }
  async return() {
    return this.#e.return();
  }
  async throw(e) {
    return this.#e.throw(e);
  }
  [Symbol.asyncIterator]() {
    return this;
  }
}, "U");
var je = /* @__PURE__ */ __name(class {
  #e;
  constructor(e) {
    this.#e = Ar(e);
  }
  async next() {
    return this.#e.next();
  }
  async return() {
    return this.#e.return();
  }
  async throw(e) {
    return this.#e.throw(e);
  }
  [Symbol.asyncIterator]() {
    return this;
  }
}, "je");
async function* It(t, e, r) {
  let s = e;
  for (s instanceof D && (yield s.data); s.after; ) {
    let n = ft`Set.paginate(${s.after})`;
    s = (await t.query(n, r)).data, yield s.data;
  }
}
__name(It, "It");
async function* Cr(t, e, r) {
  let s = await e();
  if (s instanceof D || s instanceof L) {
    for await (let n of It(t, s, r))
      yield n;
    return;
  }
  yield [s];
}
__name(Cr, "Cr");
async function* Ar(t) {
  for await (let e of t)
    for (let r of e)
      yield r;
}
__name(Ar, "Ar");
function Ae(t) {
  return typeof t.token == "string";
}
__name(Ae, "Ae");
var ne = /* @__PURE__ */ __name(class {
  token;
  constructor(e) {
    this.token = e;
  }
}, "ne");
var Ce = /* @__PURE__ */ __name(class {
  events;
  cursor;
  hasNext;
  stats;
  constructor({ events: e, cursor: r, has_next: s, stats: n }) {
    this.events = this.#e(e), this.cursor = r, this.hasNext = s, this.stats = n;
  }
  *#e(e) {
    for (let r of e) {
      if (r.type === "error")
        throw O(r);
      yield r;
    }
  }
}, "Ce");
var H = /* @__PURE__ */ __name(class {
  static encode(e) {
    return ye(e);
  }
  static encodeInterpolation(e) {
    return Me(e);
  }
  static decode(e, r) {
    return JSON.parse(e, (s, n) => {
      if (n == null)
        return null;
      if (n["@mod"])
        return new W(n["@mod"]);
      if (n["@doc"]) {
        if (typeof n["@doc"] == "string") {
          let [i, d] = n["@doc"].split(":");
          return new M({ coll: i, id: d });
        }
        let o = n["@doc"];
        return o.id ? new fe(o) : new pe(o);
      } else if (n["@ref"]) {
        let o = n["@ref"], i;
        return o.id ? i = new M(o) : i = new Y(o), "exists" in o && o.exists === false ? new re(i, o.cause) : i;
      } else {
        if (n["@set"])
          return typeof n["@set"] == "string" ? new L(n["@set"]) : new D(n["@set"]);
        if (n["@int"])
          return Number(n["@int"]);
        if (n["@long"]) {
          let o = BigInt(n["@long"]);
          return r.long_type === "number" ? ((o > Number.MAX_SAFE_INTEGER || o < Number.MIN_SAFE_INTEGER) && console.warn("Value is too large to be represented as a number. Returning as Number with loss of precision. Use long_type 'bigint' instead."), Number(o)) : o;
        } else {
          if (n["@double"])
            return Number(n["@double"]);
          if (n["@date"])
            return N.from(n["@date"]);
          if (n["@time"])
            return q.from(n["@time"]);
          if (n["@object"])
            return n["@object"];
          if (n["@stream"])
            return new ne(n["@stream"]);
          if (n["@bytes"])
            return vr(n["@bytes"]);
        }
      }
      return n;
    });
  }
}, "H");
var Ht = BigInt("-9223372036854775808");
var Vt = BigInt("9223372036854775807");
var qt = -(2 ** 31);
var Nt = 2 ** 31 - 1;
var b = { bigint: (t) => {
  if (t < Ht || t > Vt)
    throw new RangeError("BigInt value exceeds max magnitude for a 64-bit Fauna long. Use a 'number' to represent doubles beyond that limit.");
  return t >= qt && t <= Nt ? { "@int": t.toString() } : { "@long": t.toString() };
}, number: (t) => {
  if (t === Number.POSITIVE_INFINITY || t === Number.NEGATIVE_INFINITY)
    throw new RangeError(`Cannot convert ${t} to a Fauna type.`);
  return Number.isInteger(t) ? t >= qt && t <= Nt ? { "@int": t.toString() } : Number.isSafeInteger(t) ? { "@long": t.toString() } : { "@double": t.toString() } : { "@double": t.toString() };
}, string: (t) => t, object: (t) => {
  let e = false, r = {};
  for (let s in t)
    s.startsWith("@") && (e = true), t[s] !== void 0 && (r[s] = ye(t[s]));
  return e ? { "@object": r } : r;
}, array: (t) => t.map(ye), date: (t) => ({ "@time": t.toISOString() }), faunadate: (t) => ({ "@date": t.dateString }), faunatime: (t) => ({ "@time": t.isoString }), module: (t) => ({ "@mod": t.name }), documentReference: (t) => ({ "@ref": { id: t.id, coll: { "@mod": t.coll.name } } }), document: (t) => ({ "@ref": { id: t.id, coll: { "@mod": t.coll.name } } }), namedDocumentReference: (t) => ({ "@ref": { name: t.name, coll: { "@mod": t.coll.name } } }), namedDocument: (t) => ({ "@ref": { name: t.name, coll: { "@mod": t.coll.name } } }), set: (t) => {
  throw new y("Page could not be encoded. Fauna does not accept encoded Set values, yet. Use Page.data and Page.after as arguments, instead.");
}, streamToken: (t) => t.token, bytes: (t) => ({ "@bytes": Fr(t) }) };
var ye = /* @__PURE__ */ __name((t) => {
  switch (typeof t) {
    case "bigint":
      return b.bigint(t);
    case "string":
      return b.string(t);
    case "number":
      return b.number(t);
    case "boolean":
      return t;
    case "object":
      if (t == null)
        return null;
      if (Array.isArray(t))
        return b.array(t);
      if (t instanceof Date)
        return b.date(t);
      if (t instanceof N)
        return b.faunadate(t);
      if (t instanceof q)
        return b.faunatime(t);
      if (t instanceof W)
        return b.module(t);
      if (t instanceof fe)
        return b.document(t);
      if (t instanceof M)
        return b.documentReference(t);
      if (t instanceof pe)
        return b.namedDocument(t);
      if (t instanceof Y)
        return b.namedDocumentReference(t);
      if (t instanceof re)
        return ye(t.ref);
      if (t instanceof D)
        return b.set(t);
      if (t instanceof L)
        return b.set(t);
      if (t instanceof ne)
        return b.streamToken(t);
      if (t instanceof Uint8Array || t instanceof ArrayBuffer)
        return b.bytes(t);
      if (ArrayBuffer.isView(t))
        throw new y("Error encoding TypedArray to Fauna Bytes. Convert your TypedArray to Uint8Array or ArrayBuffer before passing it to Fauna. See https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/TypedArray");
      if (t instanceof P)
        throw new TypeError("Cannot encode instance of type 'Query'. Try using TaggedTypeFormat.encodeInterpolation instead.");
      return b.object(t);
    default:
      throw new TypeError(`Passing ${typeof t} as a QueryArgument is not supported`);
  }
}, "ye");
var Me = /* @__PURE__ */ __name((t) => {
  switch (typeof t) {
    case "bigint":
    case "string":
    case "number":
    case "boolean":
      return Dt(ye(t));
    case "object":
      return t == null || t instanceof Date || t instanceof N || t instanceof q || t instanceof W || t instanceof M || t instanceof Y || t instanceof D || t instanceof L || t instanceof ne || t instanceof Uint8Array || t instanceof ArrayBuffer || ArrayBuffer.isView(t) ? Dt(ye(t)) : t instanceof re ? Me(t.ref) : t instanceof P ? Qr(t) : Array.isArray(t) ? Rr(t) : Pr(t);
    default:
      throw new TypeError(`Passing ${typeof t} as a QueryArgument is not supported`);
  }
}, "Me");
var Pr = /* @__PURE__ */ __name((t) => {
  let e = {};
  for (let r in t)
    t[r] !== void 0 && (e[r] = Me(t[r]));
  return { object: e };
}, "Pr");
var Rr = /* @__PURE__ */ __name((t) => ({ array: t.map(Me) }), "Rr");
var Qr = /* @__PURE__ */ __name((t) => t.encode(), "Qr");
var Dt = /* @__PURE__ */ __name((t) => ({ value: t }), "Dt");
function vr(t) {
  return pt.default.toByteArray(t);
}
__name(vr, "vr");
function Fr(t) {
  let e = t instanceof Uint8Array ? t : new Uint8Array(t);
  return pt.default.fromByteArray(e);
}
__name(Fr, "Fr");
function ft(t, ...e) {
  return new P(t, ...e);
}
__name(ft, "ft");
var P = /* @__PURE__ */ __name(class {
  #e;
  #t;
  #r;
  constructor(e, ...r) {
    if (e.length === 0 || e.length !== r.length + 1)
      throw new Error("invalid query constructed");
    this.#e = e, this.#t = r, this.#r = void 0;
  }
  encode() {
    if (this.#e.length === 1)
      return { fql: [this.#e[0]] };
    let e = this.#e.flatMap((r, s) => {
      if (s === this.#e.length - 1)
        return r === "" ? [] : [r];
      let n = this.#t[s], o = H.encodeInterpolation(n);
      return [r, o];
    });
    return e = e.filter((r) => r !== ""), { fql: e };
  }
}, "P");
var jt = "2.4.0";
var We;
try {
  We = nt("node:os");
} catch {
  We = void 0;
}
var yt = /* @__PURE__ */ __name(() => {
  let t = { driver: ["javascript", jt].join("-"), env: "unknown", os: "unknown", runtime: "unknown" };
  try {
    let e = typeof window > "u" && typeof process < "u" && process.versions != null && process.versions.node != null, r = typeof window < "u" && typeof window.document < "u", s = typeof self == "object" && self.constructor && self.constructor.name === "DedicatedWorkerGlobalScope";
    e ? (t.runtime = ["nodejs", process.version].join("-"), t.env = kr(), t.os = [We.platform(), We.release()].join("-")) : s ? (t.runtime = Mt(navigator), t.env = "Service Worker", t.os = Wt(navigator)) : r ? (t.runtime = Mt(navigator), t.env = "browser", t.os = Wt(navigator)) : typeof EdgeRuntime != "string" && (t.runtime = "Vercel Edge Runtime", t.env = "edge");
  } catch {
  }
  return Object.entries(t).filter(([e, r]) => r !== "unknown").map((e) => e.join("=")).join("; ");
}, "yt");
var Mt = /* @__PURE__ */ __name((t) => {
  let e = t.appName, r = "" + parseFloat(t.appVersion), s, n, o;
  return (n = t.userAgent.indexOf("Opera")) != -1 ? (e = "Opera", r = t.userAgent.substring(n + 6), (n = t.userAgent.indexOf("Version")) != -1 && (r = t.userAgent.substring(n + 8))) : (n = t.userAgent.indexOf("MSIE")) != -1 ? (e = "Microsoft Internet Explorer", r = t.userAgent.substring(n + 5)) : e == "Netscape" && t.userAgent.indexOf("Trident/") != -1 ? (e = "Microsoft Internet Explorer", r = t.userAgent.substring(n + 5), (n = t.userAgent.indexOf("rv:")) != -1 && (r = t.userAgent.substring(n + 3))) : (n = t.userAgent.indexOf("Chrome")) != -1 ? (e = "Chrome", r = t.userAgent.substring(n + 7)) : (n = t.userAgent.indexOf("Safari")) != -1 ? (e = "Safari", r = t.userAgent.substring(n + 7), (n = t.userAgent.indexOf("Version")) != -1 && (r = t.userAgent.substring(n + 8)), t.userAgent.indexOf("CriOS") != -1 && (e = "Chrome")) : (n = t.userAgent.indexOf("Firefox")) != -1 ? (e = "Firefox", r = t.userAgent.substring(n + 8)) : (s = t.userAgent.lastIndexOf(" ") + 1) < (n = t.userAgent.lastIndexOf("/")) && (e = t.userAgent.substring(s, n), r = t.userAgent.substring(n + 1), e.toLowerCase() == e.toUpperCase() && (e = t.appName)), (o = r.indexOf(";")) != -1 && (r = r.substring(0, o)), (o = r.indexOf(" ")) != -1 && (r = r.substring(0, o)), (o = r.indexOf(")")) != -1 && (r = r.substring(0, o)), [e, r].join("-");
}, "Mt");
var Wt = /* @__PURE__ */ __name((t) => {
  let e = "unknown", r = [{ s: "Windows 10", r: /(Windows 10.0|Windows NT 10.0)/ }, { s: "Windows 8.1", r: /(Windows 8.1|Windows NT 6.3)/ }, { s: "Windows 8", r: /(Windows 8|Windows NT 6.2)/ }, { s: "Windows 7", r: /(Windows 7|Windows NT 6.1)/ }, { s: "Windows Vista", r: /Windows NT 6.0/ }, { s: "Windows Server 2003", r: /Windows NT 5.2/ }, { s: "Windows XP", r: /(Windows NT 5.1|Windows XP)/ }, { s: "Windows 2000", r: /(Windows NT 5.0|Windows 2000)/ }, { s: "Windows ME", r: /(Win 9x 4.90|Windows ME)/ }, { s: "Windows 98", r: /(Windows 98|Win98)/ }, { s: "Windows 95", r: /(Windows 95|Win95|Windows_95)/ }, { s: "Windows NT 4.0", r: /(Windows NT 4.0|WinNT4.0|WinNT|Windows NT)/ }, { s: "Windows CE", r: /Windows CE/ }, { s: "Windows 3.11", r: /Win16/ }, { s: "Android", r: /Android/ }, { s: "Open BSD", r: /OpenBSD/ }, { s: "Sun OS", r: /SunOS/ }, { s: "Chrome OS", r: /CrOS/ }, { s: "Linux", r: /(Linux|X11(?!.*CrOS))/ }, { s: "iOS", r: /(iPhone|iPad|iPod)/ }, { s: "Mac OS X", r: /Mac OS X/ }, { s: "Mac OS", r: /(Mac OS|MacPPC|MacIntel|Mac_PowerPC|Macintosh)/ }, { s: "QNX", r: /QNX/ }, { s: "UNIX", r: /UNIX/ }, { s: "BeOS", r: /BeOS/ }, { s: "OS/2", r: /OS\/2/ }, { s: "Search Bot", r: /(nuhk|Googlebot|Yammybot|Openbot|Slurp|MSNBot|Ask Jeeves\/Teoma|ia_archiver)/ }];
  for (let n in r) {
    let o = r[n];
    if (o.r.test(t.userAgent)) {
      e = o.s;
      break;
    }
  }
  let s = "unknown";
  if (/Windows/.test(e)) {
    let n = /Windows (.*)/.exec(e);
    n && (s = n[1]), e = "Windows";
  }
  switch (e) {
    case "Mac OS":
    case "Mac OS X":
    case "Android": {
      let n = /(?:Android|Mac OS|Mac OS X|MacPPC|MacIntel|Mac_PowerPC|Macintosh) ([._\d]+)/.exec(t.userAgent);
      n && (s = n[1]);
      break;
    }
    case "iOS": {
      let n = /OS (\d+)_(\d+)_?(\d+)?/.exec(t.appVersion);
      n && (s = n[1] + "." + n[2] + "." + (n[3] ?? 0));
      break;
    }
  }
  return [e, s].join("-");
}, "Wt");
var Or = typeof window < "u" ? window : typeof globalThis < "u" ? globalThis : typeof global < "u" ? global : self;
var kr = /* @__PURE__ */ __name(() => {
  if (!(typeof process < "u" && process && process.env && typeof process.env == "object"))
    return "unknown";
  let e = [{ name: "Netlify", check: function() {
    return !!process.env.NETLIFY_IMAGES_CDN_DOMAIN;
  } }, { name: "Vercel", check: function() {
    return !!process.env.VERCEL;
  } }, { name: "Heroku", check: function() {
    return !!process.env.PATH && process.env.PATH.indexOf(".heroku") !== -1;
  } }, { name: "AWS Lambda", check: function() {
    return !!process.env.AWS_LAMBDA_FUNCTION_VERSION;
  } }, { name: "GCP Cloud Functions", check: function() {
    return !!process.env._ && process.env._.indexOf("google") !== -1;
  } }, { name: "GCP Compute Instances", check: function() {
    return !!process.env.GOOGLE_CLOUD_PROJECT;
  } }, { name: "Azure Cloud Functions", check: function() {
    return !!process.env.WEBSITE_FUNCTIONS_AZUREMONITOR_CATEGORIES;
  } }, { name: "Azure Compute", check: function() {
    return !!process.env.ORYX_ENV_TYPE && !!process.env.WEBSITE_INSTANCE_ID && process.env.ORYX_ENV_TYPE === "AppService";
  } }, { name: "Mongo Stitch", check: function() {
    return typeof Or?.StitchError == "function";
  } }, { name: "Render", check: function() {
    return !!process.env.RENDER_SERVICE_ID;
  } }, { name: "Begin", check: function() {
    return !!process.env.BEGIN_DATA_SCOPE_ID;
  } }].find((r) => r.check());
  return e ? e.name : "unknown";
}, "kr");
var gt = /* @__PURE__ */ __name(async (t, { maxAttempts: e, maxBackoff: r, shouldRetry: s = /* @__PURE__ */ __name(() => true, "s"), attempt: n = 0, sleepFn: o = setTimeout }) => {
  let i = n > 0 ? Math.min(Math.random() * 2 ** n, r) * 1e3 : 0;
  n += 1;
  try {
    return await t();
  } catch (d) {
    if (n >= e || s(d) !== true)
      throw d;
    return await new Promise((c) => o(c, i)), gt(t, { maxAttempts: e, maxBackoff: r, shouldRetry: s, attempt: n, sleepFn: o });
  }
}, "gt");
var Lt = /* @__PURE__ */ __name((t) => t instanceof Object && "data" in t, "Lt");
var ht = /* @__PURE__ */ __name((t) => t instanceof Object && "error" in t && t.error instanceof Object && "code" in t.error && "message" in t.error, "ht");
var Tt = { client_timeout_buffer_ms: 5e3, format: "tagged", http2_session_idle_ms: 5e3, http2_max_streams: 100, long_type: "number", fetch_keepalive: false, query_timeout_ms: 5e3, max_attempts: 3, max_backoff: 20 };
var Be;
var _;
var B;
var A;
var J;
var Re;
var bt;
var Qe;
var St;
var $e;
var Ut;
var Ge;
var Bt;
var ze;
var $t;
var Ye;
var Gt;
var Je;
var zt;
var xt = /* @__PURE__ */ __name(class {
  constructor(e, r) {
    u(this, Re);
    u(this, Qe);
    u(this, $e);
    u(this, Ge);
    u(this, ze);
    u(this, Ye);
    u(this, Je);
    u(this, _, void 0);
    u(this, B, void 0);
    u(this, A, void 0);
    u(this, J, false);
    f(this, _, { ...Tt, ...e, secret: l(this, $e, Ut).call(this, e), endpoint: l(this, Ge, Bt).call(this, e) }), l(this, Je, zt).call(this), r ? f(this, B, r) : f(this, B, ut({ url: a(this, _).endpoint.toString(), http2_session_idle_ms: a(this, _).http2_session_idle_ms, http2_max_streams: a(this, _).http2_max_streams, fetch_keepalive: a(this, _).fetch_keepalive }));
  }
  get lastTxnTs() {
    return a(this, A);
  }
  set lastTxnTs(e) {
    e !== void 0 && f(this, A, a(this, A) ? Math.max(e, a(this, A)) : e);
  }
  get clientConfiguration() {
    let { ...e } = a(this, _);
    return e;
  }
  close() {
    if (a(this, J))
      throw new v("Your client is closed. You cannot close it again.");
    a(this, B).close(), f(this, J, true);
  }
  paginate(e, r) {
    return e instanceof P ? U.fromQuery(this, e, r) : U.fromPageable(this, e, r);
  }
  async query(e, r) {
    if (a(this, J))
      throw new v("Your client is closed. No further requests can be issued.");
    let s = { query: e.encode() };
    return r?.arguments && (s.arguments = H.encode(r.arguments)), l(this, Re, bt).call(this, s, r);
  }
  stream(e, r) {
    if (a(this, J))
      throw new v("Your client is closed. No further requests can be issued.");
    let s = a(this, B);
    if (dt(s)) {
      let n = { ...a(this, _), httpStreamClient: s, ...r };
      if (n.cursor !== void 0 && e instanceof P)
        throw new y("The `cursor` configuration can only be used with a stream token.");
      let o = e instanceof P ? () => this.query(e).then((i) => i.data) : e;
      return new Ue(o, n);
    } else
      throw new y("Streaming is not supported by this client.");
  }
  feed(e, r) {
    if (a(this, J))
      throw new v("Your client is closed. No further requests can be issued.");
    let s = { ...a(this, _), httpClient: a(this, B), ...r }, n = e instanceof P ? () => this.query(e).then((o) => o.data) : e;
    return new Pe(n, s);
  }
}, "xt");
var Le = xt;
Be = /* @__PURE__ */ new WeakMap(), _ = /* @__PURE__ */ new WeakMap(), B = /* @__PURE__ */ new WeakMap(), A = /* @__PURE__ */ new WeakMap(), J = /* @__PURE__ */ new WeakMap(), Re = /* @__PURE__ */ new WeakSet(), bt = /* @__PURE__ */ __name(async function(e, r, s = 0) {
  let n = this.clientConfiguration.max_backoff ?? Tt.max_backoff, o = this.clientConfiguration.max_attempts ?? Tt.max_attempts, i = Math.min(Math.random() * 2 ** s, n) * 1e3;
  s += 1;
  try {
    return await l(this, ze, $t).call(this, e, r, s);
  } catch (d) {
    if (d instanceof V && s < o)
      return await Kt(i), l(this, Re, bt).call(this, e, r, s);
    throw d;
  }
}, "bt"), Qe = /* @__PURE__ */ new WeakSet(), St = /* @__PURE__ */ __name(function(e) {
  if (e instanceof y || e instanceof w || e instanceof F || e instanceof h)
    return e;
  if (ct(e)) {
    if (ht(e.body)) {
      let r = e.body, s = e.status;
      return O(r, s);
    }
    return new F({ message: `Response is in an unkown format: ${e.body}`, httpStatus: e.status });
  }
  return new y("A client level error occurred. Fauna was not called.", { cause: e });
}, "St"), $e = /* @__PURE__ */ new WeakSet(), Ut = /* @__PURE__ */ __name(function(e) {
  let r;
  typeof process < "u" && process && typeof process == "object" && process.env && typeof process.env == "object" && (r = process.env.FAUNA_SECRET);
  let s = e?.secret ?? r;
  if (s === void 0)
    throw new TypeError("You must provide a secret to the driver. Set it in an environmental variable named FAUNA_SECRET or pass it to the Client constructor.");
  return s;
}, "Ut"), Ge = /* @__PURE__ */ new WeakSet(), Bt = /* @__PURE__ */ __name(function(e) {
  if (e && "endpoint" in e && e.endpoint === void 0)
    throw new TypeError("ClientConfiguration option endpoint must be defined.");
  let r;
  return typeof process < "u" && process && typeof process == "object" && process.env && typeof process.env == "object" && (r = process.env.FAUNA_ENDPOINT ? new URL(process.env.FAUNA_ENDPOINT) : void 0), e?.endpoint ?? r ?? at.default;
}, "Bt"), ze = /* @__PURE__ */ new WeakSet(), $t = /* @__PURE__ */ __name(async function(e, r, s = 0) {
  try {
    let n = { ...a(this, _), ...r }, o = { Authorization: `Bearer ${n.secret}` };
    l(this, Ye, Gt).call(this, n, o);
    let i = n.format === "tagged", d = n.query_timeout_ms + a(this, _).client_timeout_buffer_ms, c = await a(this, B).request({ client_timeout_ms: d, data: e, headers: o, method: "POST" }), m;
    try {
      if (m = { ...c, body: i ? H.decode(c.body, { long_type: n.long_type }) : JSON.parse(c.body) }, m.body.query_tags) {
        let x = m.body.query_tags.split(",").map((T) => T.split("="));
        m.body.query_tags = Object.fromEntries(x);
      }
    } catch (x) {
      throw new F({ message: `Error parsing response as JSON: ${x}`, httpStatus: c.status });
    }
    if (!Lt(m.body))
      throw l(this, Qe, St).call(this, m);
    let p = m.body.txn_ts;
    (a(this, A) === void 0 && p !== void 0 || p !== void 0 && a(this, A) !== void 0 && a(this, A) < p) && f(this, A, p);
    let g = m.body;
    return g.stats && (g.stats.attempts = s), g;
  } catch (n) {
    throw l(this, Qe, St).call(this, n);
  }
}, "$t"), Ye = /* @__PURE__ */ new WeakSet(), Gt = /* @__PURE__ */ __name(function(e, r) {
  let s = /* @__PURE__ */ __name((n, o, i = (d) => String(d)) => {
    o !== void 0 && (r[n] = i(o));
  }, "s");
  s("x-format", e.format), s("x-typecheck", e.typecheck), s("x-performance-hints", e.performance_hints), s("x-query-timeout-ms", e.query_timeout_ms), s("x-linearized", e.linearized), s("x-max-contention-retries", e.max_contention_retries), s("traceparent", e.traceparent), s("x-query-tags", e.query_tags, (n) => Object.entries(n).map((o) => o.join("=")).join(",")), s("x-last-txn-ts", a(this, A), (n) => n), s("x-driver-env", a(xt, Be));
}, "Gt"), Je = /* @__PURE__ */ new WeakSet(), zt = /* @__PURE__ */ __name(function() {
  let e = a(this, _);
  if (["client_timeout_buffer_ms", "endpoint", "format", "http2_session_idle_ms", "long_type", "query_timeout_ms", "fetch_keepalive", "http2_max_streams", "max_backoff", "max_attempts"].forEach((s) => {
    if (e[s] === void 0)
      throw new TypeError(`ClientConfiguration option '${s}' must be defined.`);
  }), e.http2_max_streams <= 0)
    throw new RangeError("'http2_max_streams' must be greater than zero.");
  if (e.client_timeout_buffer_ms <= 0)
    throw new RangeError("'client_timeout_buffer_ms' must be greater than zero.");
  if (e.query_timeout_ms <= 0)
    throw new RangeError("'query_timeout_ms' must be greater than zero.");
  if (e.max_backoff <= 0)
    throw new RangeError("'max_backoff' must be greater than zero.");
  if (e.max_attempts <= 0)
    throw new RangeError("'max_attempts' must be greater than zero.");
}, "zt"), u(Le, Be, yt());
var Ue = /* @__PURE__ */ __name(class {
  closed = false;
  #e;
  #t = 0;
  #r;
  #n;
  #s;
  #o;
  #a;
  constructor(e, r) {
    Ae(e) ? this.#r = () => Promise.resolve(e) : this.#r = e, this.#e = r, this.#u();
  }
  start(e, r) {
    if (typeof e != "function")
      throw new TypeError(`Expected a function as the 'onEvent' argument, but received ${typeof e}. Please provide a valid function.`);
    if (r && typeof r != "function")
      throw new TypeError(`Expected a function as the 'onError' argument, but received ${typeof r}. Please provide a valid function.`);
    (async () => {
      try {
        for await (let n of this)
          e(n);
      } catch (n) {
        r && r(n);
      }
    })();
  }
  async *[Symbol.asyncIterator]() {
    if (this.closed)
      throw new y("The stream has been closed and cannot be reused.");
    for (this.#a || (this.#a = await this.#r().then((e) => {
      if (!Ae(e))
        throw new y(`Error requesting a stream token. Expected a EventSource as the query result, but received ${typeof e}. Your query must return the result of '<Set>.eventSource' or '<Set>.eventsOn')
Query result: ${JSON.stringify(e, null)}`);
      return e;
    })), this.#t = 1; !this.closed; ) {
      let e = Math.min(Math.random() * 2 ** this.#t, this.#e.max_backoff) * 1e3;
      try {
        for await (let r of this.#i())
          yield r;
      } catch (r) {
        if (r instanceof Q || this.#t >= this.#e.max_attempts)
          throw this.close(), r;
        this.#t += 1, await Kt(e);
      }
    }
  }
  close() {
    this.#o && (this.#o.close(), this.#o = void 0), this.closed = true;
  }
  get last_ts() {
    return this.#n;
  }
  async *#i() {
    let e = this.#a, r = { Authorization: `Bearer ${this.#e.secret}` }, s = this.#e.httpStreamClient.stream({ data: { token: e.token, cursor: this.#s || this.#e.cursor }, headers: r, method: "POST" });
    this.#o = s;
    for await (let n of s.read) {
      let o = H.decode(n, { long_type: this.#e.long_type });
      if (o.type === "error")
        throw this.close(), O(o);
      this.#n = o.txn_ts, this.#s = o.cursor, o.type === "start" && (o.type = "status"), !(!this.#e.status_events && o.type === "status") && (yield o);
    }
  }
  #u() {
    let e = this.#e;
    if (["long_type", "httpStreamClient", "max_backoff", "max_attempts", "secret"].forEach((s) => {
      if (e[s] === void 0)
        throw new TypeError(`ClientConfiguration option '${s}' must be defined.`);
    }), e.max_backoff <= 0)
      throw new RangeError("'max_backoff' must be greater than zero.");
    if (e.max_attempts <= 0)
      throw new RangeError("'max_attempts' must be greater than zero.");
  }
}, "Ue");
var Xe;
var ge;
var S;
var se;
var he;
var Te;
var Ze;
var Yt;
var Ke;
var Jt;
var et;
var Xt;
var tt;
var Zt;
var wt = /* @__PURE__ */ __name(class {
  constructor(e, r) {
    u(this, Ze);
    u(this, Ke);
    u(this, et);
    u(this, tt);
    u(this, ge, void 0);
    u(this, S, void 0);
    u(this, se, void 0);
    u(this, he, void 0);
    u(this, Te, void 0);
    Ae(e) ? f(this, ge, () => Promise.resolve(e)) : f(this, ge, e), f(this, S, r), f(this, se, r.cursor), l(this, tt, Zt).call(this);
  }
  async *[Symbol.asyncIterator]() {
    for (; !a(this, Te); )
      yield await this.nextPage();
  }
  async nextPage() {
    if (a(this, Te))
      throw new y("The event feed has no more pages to fetch.");
    let { httpClient: e } = a(this, S), r = await l(this, Ke, Jt).call(this), s = await gt(() => e.request(r), { maxAttempts: a(this, S).max_attempts, maxBackoff: a(this, S).max_backoff, shouldRetry: (i) => i instanceof V }), n;
    try {
      n = H.decode(s.body, { long_type: a(this, S).long_type });
    } catch (i) {
      throw new F({ message: `Error parsing response as JSON: ${i}`, httpStatus: s.status });
    }
    if (ht(n))
      throw O(n, s.status);
    let o = new Ce(n);
    return f(this, se, o.cursor), f(this, Te, !o.hasNext), o;
  }
  async *flatten() {
    for await (let e of this)
      for (let r of e.events)
        yield r;
  }
}, "wt");
var Pe = wt;
Xe = /* @__PURE__ */ new WeakMap(), ge = /* @__PURE__ */ new WeakMap(), S = /* @__PURE__ */ new WeakMap(), se = /* @__PURE__ */ new WeakMap(), he = /* @__PURE__ */ new WeakMap(), Te = /* @__PURE__ */ new WeakMap(), Ze = /* @__PURE__ */ new WeakSet(), Yt = /* @__PURE__ */ __name(function() {
  return { Authorization: `Bearer ${a(this, S).secret}`, "x-format": "tagged", "x-driver-env": a(wt, Xe), "x-query-timeout-ms": a(this, S).query_timeout_ms.toString() };
}, "Yt"), Ke = /* @__PURE__ */ new WeakSet(), Jt = /* @__PURE__ */ __name(async function() {
  a(this, he) || f(this, he, await l(this, et, Xt).call(this, a(this, ge)));
  let r = { headers: l(this, Ze, Yt).call(this), client_timeout_ms: a(this, S).client_timeout_buffer_ms + a(this, S).query_timeout_ms, data: { token: a(this, he).token }, method: "POST", path: j.EVENT_FEED };
  return a(this, S).page_size && (r.data.page_size = a(this, S).page_size), a(this, se) ? r.data.cursor = a(this, se) : a(this, S).start_ts && (r.data.start_ts = a(this, S).start_ts), r;
}, "Jt"), et = /* @__PURE__ */ new WeakSet(), Xt = /* @__PURE__ */ __name(async function(e) {
  return await e().then((r) => {
    if (!Ae(r))
      throw new y(`Error requesting a stream token. Expected a EventSource as the query result, but received ${typeof r}. Your query must return the result of '<Set>.eventSource' or '<Set>.eventsOn')
Query result: ${JSON.stringify(r, null)}`);
    return r;
  });
}, "Xt"), tt = /* @__PURE__ */ new WeakSet(), Zt = /* @__PURE__ */ __name(function() {
  let e = a(this, S);
  if (["long_type", "httpClient", "max_backoff", "max_attempts", "client_timeout_buffer_ms", "query_timeout_ms", "secret"].forEach((s) => {
    if (e[s] === void 0)
      throw new TypeError(`ClientConfiguration option '${s}' must be defined.`);
  }), e.max_backoff <= 0)
    throw new RangeError("'max_backoff' must be greater than zero.");
  if (e.max_attempts <= 0)
    throw new RangeError("'max_attempts' must be greater than zero.");
  if (e.query_timeout_ms <= 0)
    throw new RangeError("'query_timeout_ms' must be greater than zero.");
  if (e.client_timeout_buffer_ms < 0)
    throw new RangeError("'client_timeout_buffer_ms' must be greater than or equal to zero.");
  if (e.start_ts !== void 0 && e.cursor !== void 0)
    throw new TypeError("Only one of 'start_ts' or 'cursor' can be defined in the client configuration.");
  if (e.cursor !== void 0 && typeof e.cursor != "string")
    throw new TypeError("'cursor' must be a string.");
}, "Zt"), u(Pe, Xe, yt());
function Kt(t) {
  return new Promise((e) => setTimeout(e, t));
}
__name(Kt, "Kt");

// src/utils/log.js
var logQueue = [];
var isSendingLogs = false;
var batchCounter = 0;
function generateBatchID() {
  const now = /* @__PURE__ */ new Date();
  const year = now.getFullYear();
  const month = String(now.getMonth() + 1).padStart(2, "0");
  const day = String(now.getDate()).padStart(2, "0");
  const hour = String(now.getHours()).padStart(2, "0");
  const batchID = `${year}${month}${day}${hour}${String(batchCounter).padStart(9, "0")}`;
  batchCounter++;
  return batchID;
}
__name(generateBatchID, "generateBatchID");
async function sendToLogQueue(env, logEntry) {
  if (!env?.MY_QUEUE) {
    console.error("Queue not configured");
    return;
  }
  logQueue.push({
    ...logEntry,
    timestamp: logEntry.timestamp || (/* @__PURE__ */ new Date()).toISOString()
  });
  if (isSendingLogs)
    return;
  isSendingLogs = true;
  const MAX_SUBREQUESTS = 45;
  const BATCH_SIZE = 50;
  const MAX_RETRIES = 3;
  let subrequestsMade = 0;
  try {
    while (logQueue.length > 0) {
      if (subrequestsMade >= MAX_SUBREQUESTS) {
        console.log("sendToLogQueue:Maximum subrequest limit reached, exiting processing");
        break;
      }
      const batch = logQueue.splice(0, BATCH_SIZE);
      const batchID = generateBatchID();
      const messages = batch.map((entry) => ({ body: JSON.stringify(entry) }));
      let retries = 0;
      while (retries < MAX_RETRIES) {
        try {
          await env.MY_QUEUE.sendBatch(messages);
          subrequestsMade++;
          break;
        } catch (error) {
          retries++;
          console.error(`sendToLogQueue: Error sending batch to queue with Batch ID: ${batchID} (attempt ${retries}):`, error);
          if (retries === MAX_RETRIES) {
            console.error(`sendToLogQueue: Max retries reached, skipping batch with Batch ID: ${batchID}`);
          } else {
            await new Promise((resolve) => setTimeout(resolve, 1e3 * retries));
          }
        }
        if (subrequestsMade >= MAX_SUBREQUESTS) {
          console.log("sendToLogQueue: Maximum subrequest limit reached during retries, exiting processing");
          break;
        }
      }
      if (subrequestsMade >= MAX_SUBREQUESTS) {
        break;
      }
    }
  } catch (error) {
    console.error("sendToLogQueue: Error sending to queue:", error);
  } finally {
    isSendingLogs = false;
  }
}
__name(sendToLogQueue, "sendToLogQueue");
var responseText = await response.text();
console.log(`Response Status: ${response.status} ${response.statusText}`);
console.log(`Response Body: ${responseText}`);
if (lastFetchTime) {
  const fromDateString = new Date(lastFetchTime).toISOString();
  requestBody = { from: fromDateString };
} else {
  const thirtyDaysAgo = new Date(Date.now() - 30 * 24 * 60 * 60 * 1e3);
  const thirtyDaysAgoString = thirtyDaysAgo.toISOString();
  requestBody = { from: thirtyDaysAgoString };
}
try {
  if (response.ok) {
    const responseData = JSON.parse(responseText);
    data = responseData.response.Event || [];
  } else {
    throw new Error(`Failed to fetch ${type} data: ${response.status} ${response.statusText}`);
  }
} catch (error) {
  console.error(`Error fetching ${type} data: ${error.message}`);
  console.error(`Response Body: ${responseText}`);
}

// src/cloudflare/worker-threat-intel-ingest.js
var worker_threat_intel_ingest_default = {
  async fetch(request, env, ctx) {
    console.log("Fetch event triggered");
    const d1 = env.THREAT_INTEL_DB;
    const fauna = new Le({
      secret: env.FAUNA_SECRET
      // Fauna secret from environment
    });
    console.log("Fauna client initialized");
    const url = new URL(request.url);
    const isCronRequest = ctx.scheduledTime !== void 0;
    const isMispFetchRequest = url.pathname.endsWith("/fetchmisp");
    console.log(`Request URL: ${request.url}`);
    console.log(`Is Cron Request: ${isCronRequest}`);
    console.log(`Is MISP Fetch Request: ${isMispFetchRequest}`);
    if (!isCronRequest && !isMispFetchRequest) {
      console.log("Invalid endpoint accessed");
      return new Response("This endpoint is for fetching MISP data", { status: 404 });
    }
    let response2;
    let responseText2;
    try {
      await sendToLogQueue(env, {
        level: "info",
        message: "Starting threat intel fetching process."
      });
      console.log("Starting threat intel fetching process");
      const threatIntelFeeds = [
        {
          type: "misp",
          url: "https://simp.xsight.network/events/restSearch",
          format: "misp"
        }
        // Add more feeds if needed
      ];
      let allThreatIntel = [];
      for (const feed of threatIntelFeeds) {
        console.log(`Fetching data from feed: ${feed.url}`);
        const feedData = await fetchThreatIntelData(feed.url, feed.type, env, feed.format);
        console.log(`Fetched ${feedData.length} items from feed: ${feed.url}`);
        allThreatIntel = [...allThreatIntel, ...feedData];
      }
      console.log(`Total threat intel items fetched: ${allThreatIntel.length}`);
      const relevantIndicators = filterRelevantThreatIntel(allThreatIntel);
      console.log(`Relevant indicators extracted: ${relevantIndicators.length}`);
      await storeInD1(d1, relevantIndicators, env);
      console.log("Data stored in D1 successfully");
      await storeInFaunaDB(relevantIndicators, fauna, env);
      console.log("Data stored in FaunaDB successfully");
      await sendToLogQueue(env, {
        level: "info",
        message: "Threat intel data ingestion finished successfully."
      });
      console.log("Threat intel data ingestion finished successfully");
      return new Response("Threat intel data ingestion finished successfully.", { status: 200 });
    } catch (error) {
      console.error(`Error: ${error.message}`);
      if (responseText2) {
        console.error(`Response Body: ${responseText2}`);
      }
      await sendToLogQueue(env, {
        level: "error",
        message: `Error fetching/processing threat intel data: ${error.message}`,
        stack: error.stack
      });
      return new Response(`Error fetching/processing threat intel data: ${error.message}`, { status: 500 });
    }
  }
};
async function fetchThreatIntelData(url, type2, env, format, lastFetchTime2) {
  let response2;
  let responseText2;
  try {
    console.log(`Fetching ${type2} data from ${url}`);
    await sendToLogQueue(env, {
      level: "info",
      message: `Fetching ${type2} data from ${url}.`
    });
    let data2 = [];
    if (type2 === "misp") {
      let requestBody2 = {};
      if (lastFetchTime2) {
        const fromDateString = new Date(lastFetchTime2).toISOString();
        requestBody2 = { from: fromDateString };
      } else {
        const thirtyDaysAgoString = new Date(Date.now() - 30 * 24 * 60 * 60 * 1e3).toISOString();
        requestBody2 = { from: thirtyDaysAgoString };
      }
      console.log(`Request body: ${JSON.stringify(requestBody2)}`);
      await sendToLogQueue(env, {
        level: "info",
        message: `Using filters ${JSON.stringify(requestBody2)} to fetch ${type2} data from ${url}.`
      });
      response2 = await fetch(url, {
        method: "POST",
        headers: {
          Accept: "application/json",
          "Content-Type": "application/json",
          Authorization: env.MISP_API_KEY
          // Set the API key in the authorization header
        },
        body: JSON.stringify(requestBody2)
      });
      responseText2 = await response2.text();
      console.log(`Response Status: ${response2.status} ${response2.statusText}`);
      console.log(`Response Body: ${responseText2}`);
      if (response2.ok) {
        const responseData = JSON.parse(responseText2);
        data2 = responseData.response.Event || [];
      } else {
        throw new Error(`Failed to fetch ${type2} data: ${response2.status} ${response2.statusText}`);
      }
    }
    console.log(`Successfully fetched ${data2.length} ${type2} items from ${url}`);
    await sendToLogQueue(env, {
      level: "info",
      message: `Successfully fetched ${type2} data from ${url}.`
    });
    return data2;
  } catch (error) {
    console.error(`Error fetching ${type2} data: ${error.message}`);
    if (responseText2) {
      console.error(`Response Body: ${responseText2}`);
    }
    await sendToLogQueue(env, {
      level: "error",
      message: `Error fetching ${type2} data: ${error.message}`,
      stack: error.stack
    });
    throw error;
  }
}
__name(fetchThreatIntelData, "fetchThreatIntelData");
function filterRelevantThreatIntel(stixObjects) {
  console.log("Filtering relevant threat intel");
  const relevantIndicators = [];
  stixObjects.forEach((object) => {
    if (object && object.Attribute) {
      object.Attribute.forEach((attr) => {
        relevantIndicators.push({
          type: attr.type,
          value: attr.value,
          category: attr.category,
          timestamp: attr.timestamp,
          comment: attr.comment
        });
      });
    }
  });
  console.log(`Filtered ${relevantIndicators.length} relevant indicators`);
  return relevantIndicators;
}
__name(filterRelevantThreatIntel, "filterRelevantThreatIntel");
async function storeInD1(d1, data2, env) {
  try {
    console.log("Storing data in D1");
    for (const threat of data2) {
      const searchableText = `${threat.type} ${threat.value || ""} ${threat.description || ""}`;
      await d1.prepare(
        "INSERT INTO threat_intel (type, value, category, timestamp, comment, searchable_text) VALUES (?, ?, ?, ?, ?, ?)"
      ).bind(
        threat.type,
        threat.value || null,
        threat.category || null,
        threat.timestamp || null,
        threat.comment || null,
        searchableText
      ).run();
    }
    console.log("Data stored in D1 successfully");
    await sendToLogQueue(env, {
      level: "info",
      message: "Threat intel data stored in D1 successfully."
    });
  } catch (error) {
    console.error(`Error storing data in D1: ${error.message}`);
    await sendToLogQueue(env, {
      level: "error",
      message: `Error storing threat intel in D1: ${error.message}`,
      stack: error.stack
    });
    throw error;
  }
}
__name(storeInD1, "storeInD1");
async function storeInFaunaDB(data2, fauna, env) {
  try {
    console.log("Storing data in FaunaDB");
    for (const threat of data2) {
      const query = ft`
        Threats.create({
          data: ${threat}
        })
      `;
      await fauna.query(query);
    }
    console.log("Data stored in FaunaDB successfully");
    await sendToLogQueue(env, {
      level: "info",
      message: "Threat intel data stored in FaunaDB successfully."
    });
  } catch (error) {
    console.error(`Error storing data in FaunaDB: ${error.message}`);
    await sendToLogQueue(env, {
      level: "error",
      message: `Error storing threat intel in FaunaDB: ${error.message}`,
      stack: error.stack
    });
    throw error;
  }
}
__name(storeInFaunaDB, "storeInFaunaDB");

// node_modules/wrangler/templates/middleware/middleware-ensure-req-body-drained.ts
var drainBody = /* @__PURE__ */ __name(async (request, env, _ctx, middlewareCtx) => {
  try {
    return await middlewareCtx.next(request, env);
  } finally {
    try {
      if (request.body !== null && !request.bodyUsed) {
        const reader = request.body.getReader();
        while (!(await reader.read()).done) {
        }
      }
    } catch (e) {
      console.error("Failed to drain the unused request body.", e);
    }
  }
}, "drainBody");
var middleware_ensure_req_body_drained_default = drainBody;

// node_modules/wrangler/templates/middleware/middleware-miniflare3-json-error.ts
function reduceError(e) {
  return {
    name: e?.name,
    message: e?.message ?? String(e),
    stack: e?.stack,
    cause: e?.cause === void 0 ? void 0 : reduceError(e.cause)
  };
}
__name(reduceError, "reduceError");
var jsonError = /* @__PURE__ */ __name(async (request, env, _ctx, middlewareCtx) => {
  try {
    return await middlewareCtx.next(request, env);
  } catch (e) {
    const error = reduceError(e);
    return Response.json(error, {
      status: 500,
      headers: { "MF-Experimental-Error-Stack": "true" }
    });
  }
}, "jsonError");
var middleware_miniflare3_json_error_default = jsonError;

// .wrangler/tmp/bundle-hTwk8c/middleware-insertion-facade.js
var __INTERNAL_WRANGLER_MIDDLEWARE__ = [
  middleware_ensure_req_body_drained_default,
  middleware_miniflare3_json_error_default
];
var middleware_insertion_facade_default = worker_threat_intel_ingest_default;

// node_modules/wrangler/templates/middleware/common.ts
var __facade_middleware__ = [];
function __facade_register__(...args) {
  __facade_middleware__.push(...args.flat());
}
__name(__facade_register__, "__facade_register__");
function __facade_invokeChain__(request, env, ctx, dispatch, middlewareChain) {
  const [head, ...tail] = middlewareChain;
  const middlewareCtx = {
    dispatch,
    next(newRequest, newEnv) {
      return __facade_invokeChain__(newRequest, newEnv, ctx, dispatch, tail);
    }
  };
  return head(request, env, ctx, middlewareCtx);
}
__name(__facade_invokeChain__, "__facade_invokeChain__");
function __facade_invoke__(request, env, ctx, dispatch, finalMiddleware) {
  return __facade_invokeChain__(request, env, ctx, dispatch, [
    ...__facade_middleware__,
    finalMiddleware
  ]);
}
__name(__facade_invoke__, "__facade_invoke__");

// .wrangler/tmp/bundle-hTwk8c/middleware-loader.entry.ts
var __Facade_ScheduledController__ = class {
  constructor(scheduledTime, cron, noRetry) {
    this.scheduledTime = scheduledTime;
    this.cron = cron;
    this.#noRetry = noRetry;
  }
  #noRetry;
  noRetry() {
    if (!(this instanceof __Facade_ScheduledController__)) {
      throw new TypeError("Illegal invocation");
    }
    this.#noRetry();
  }
};
__name(__Facade_ScheduledController__, "__Facade_ScheduledController__");
function wrapExportedHandler(worker) {
  if (__INTERNAL_WRANGLER_MIDDLEWARE__ === void 0 || __INTERNAL_WRANGLER_MIDDLEWARE__.length === 0) {
    return worker;
  }
  for (const middleware of __INTERNAL_WRANGLER_MIDDLEWARE__) {
    __facade_register__(middleware);
  }
  const fetchDispatcher = /* @__PURE__ */ __name(function(request, env, ctx) {
    if (worker.fetch === void 0) {
      throw new Error("Handler does not export a fetch() function.");
    }
    return worker.fetch(request, env, ctx);
  }, "fetchDispatcher");
  return {
    ...worker,
    fetch(request, env, ctx) {
      const dispatcher = /* @__PURE__ */ __name(function(type2, init) {
        if (type2 === "scheduled" && worker.scheduled !== void 0) {
          const controller = new __Facade_ScheduledController__(
            Date.now(),
            init.cron ?? "",
            () => {
            }
          );
          return worker.scheduled(controller, env, ctx);
        }
      }, "dispatcher");
      return __facade_invoke__(request, env, ctx, dispatcher, fetchDispatcher);
    }
  };
}
__name(wrapExportedHandler, "wrapExportedHandler");
function wrapWorkerEntrypoint(klass) {
  if (__INTERNAL_WRANGLER_MIDDLEWARE__ === void 0 || __INTERNAL_WRANGLER_MIDDLEWARE__.length === 0) {
    return klass;
  }
  for (const middleware of __INTERNAL_WRANGLER_MIDDLEWARE__) {
    __facade_register__(middleware);
  }
  return class extends klass {
    #fetchDispatcher = (request, env, ctx) => {
      this.env = env;
      this.ctx = ctx;
      if (super.fetch === void 0) {
        throw new Error("Entrypoint class does not define a fetch() function.");
      }
      return super.fetch(request);
    };
    #dispatcher = (type2, init) => {
      if (type2 === "scheduled" && super.scheduled !== void 0) {
        const controller = new __Facade_ScheduledController__(
          Date.now(),
          init.cron ?? "",
          () => {
          }
        );
        return super.scheduled(controller);
      }
    };
    fetch(request) {
      return __facade_invoke__(
        request,
        this.env,
        this.ctx,
        this.#dispatcher,
        this.#fetchDispatcher
      );
    }
  };
}
__name(wrapWorkerEntrypoint, "wrapWorkerEntrypoint");
var WRAPPED_ENTRY;
if (typeof middleware_insertion_facade_default === "object") {
  WRAPPED_ENTRY = wrapExportedHandler(middleware_insertion_facade_default);
} else if (typeof middleware_insertion_facade_default === "function") {
  WRAPPED_ENTRY = wrapWorkerEntrypoint(middleware_insertion_facade_default);
}
var middleware_loader_entry_default = WRAPPED_ENTRY;
export {
  __INTERNAL_WRANGLER_MIDDLEWARE__,
  middleware_loader_entry_default as default
};
//# sourceMappingURL=worker-threat-intel-ingest.js.map
