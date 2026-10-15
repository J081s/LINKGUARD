import test from "node:test";
import assert from "node:assert/strict";
import healthHandler from "../api/health.js";
import scanHandler from "../api/scan.js";

function createMockRes() {
  const res = {
    statusCode: 200,
    headers: {},
    ended: false,
    body: null,
    setHeader(key, val) {
      this.headers[key.toLowerCase()] = val;
      return this;
    },
    status(code) {
      this.statusCode = code;
      return this;
    },
    json(data) {
      this.body = data;
      this.ended = true;
      return this;
    },
    end() {
      this.ended = true;
      return this;
    }
  };
  return res;
}

test("api/health handler returns 200 and provider status", async () => {
  const req = { method: "GET" };
  const res = createMockRes();
  await healthHandler(req, res);

  assert.equal(res.statusCode, 200);
  assert.equal(res.body.success, true);
  assert.equal(res.body.backend, "Online");
  assert.ok(res.body.providers);
});

test("api/scan handler rejects non-POST methods", async () => {
  const req = { method: "GET" };
  const res = createMockRes();
  await scanHandler(req, res);

  assert.equal(res.statusCode, 405);
  assert.equal(res.body.error, "Method Not Allowed");
});

test("api/scan handler returns 400 on empty url", async () => {
  const req = { method: "POST", body: { url: "" } };
  const res = createMockRes();
  await scanHandler(req, res);

  assert.equal(res.statusCode, 400);
  assert.match(res.body.error, /Please provide a valid URL/);
});

test("api/scan handler successfully scans a URL", async () => {
  const req = { method: "POST", body: { url: "https://google.com" } };
  const res = createMockRes();
  await scanHandler(req, res);

  assert.equal(res.statusCode, 200);
  assert.equal(res.body.success, true);
  assert.equal(res.body.scannedURL, "https://google.com/");
  assert.ok(typeof res.body.riskScore === "number");
  assert.ok(res.body.status);
});
