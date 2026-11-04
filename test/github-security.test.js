import test from "node:test";
import assert from "node:assert/strict";
import worker from "../src/index.js";

const ADMIN_KEY = "local-admin-test-key";

function environment() {
  return {
    ADMIN_API_KEY: ADMIN_KEY,
    GITHUB_TOKEN: "test-placeholder-not-a-credential",
    GITHUB_ALLOWED_REPOS: "owner/private-content",
    DB: {
      prepare() {
        return {
          bind() {
            return this;
          },
          async run() {
            return { success: true };
          }
        };
      }
    }
  };
}

async function callGithub(body, mockFetch) {
  const originalFetch = globalThis.fetch;
  globalThis.fetch = mockFetch;

  try {
    return await worker.fetch(
      new Request("https://worker.example/admin/github/file", {
        method: "PUT",
        headers: {
          Authorization: `Bearer ${ADMIN_KEY}`,
          "Content-Type": "application/json"
        },
        body: JSON.stringify(body)
      }),
      environment()
    );
  } finally {
    globalThis.fetch = originalFetch;
  }
}

test("GitHub Actions dizinine yazma engellenir", async () => {
  let calls = 0;

  const response = await callGithub({
    repo: "owner/private-content",
    path: ".github/workflows/deploy.yml",
    content: "test"
  }, async () => {
    calls++;
    return Response.json({});
  });

  assert.equal(response.status, 400);
  assert.equal(calls, 0);
});

test("Git metadata dizinine yazma engellenir", async () => {
  let calls = 0;

  const response = await callGithub({
    repo: "owner/private-content",
    path: ".git/config",
    content: "test"
  }, async () => {
    calls++;
    return Response.json({});
  });

  assert.equal(response.status, 400);
  assert.equal(calls, 0);
});

test("CODEOWNERS dosyasına yazma engellenir", async () => {
  let calls = 0;

  const response = await callGithub({
    repo: "owner/private-content",
    path: "CODEOWNERS",
    content: "test"
  }, async () => {
    calls++;
    return Response.json({});
  });

  assert.equal(response.status, 400);
  assert.equal(calls, 0);
});

test("İzin verilen dosyaya yazılır ancak istemci branch seçemez", async () => {
  const requests = [];

  const response = await callGithub({
    repo: "owner/private-content",
    path: "content/catalog.json",
    content: '{"ok":true}',
    branch: "attacker-branch"
  }, async (url, options = {}) => {
    requests.push({
      url: String(url),
      options
    });

    if (options.method === "PUT") {
      return Response.json({
        content: { sha: "updated-sha" }
      });
    }

    return Response.json({
      sha: "existing-sha"
    });
  });

  assert.equal(response.status, 200);
  assert.equal(requests.length, 2);

  const put = requests.find(x => x.options.method === "PUT");
  assert.ok(put);

  const payload = JSON.parse(put.options.body);
  assert.equal(payload.content, Buffer.from('{"ok":true}').toString("base64"));
  assert.equal(Object.hasOwn(payload, "branch"), false);
});
