import test from "node:test";
import assert from "node:assert/strict";
import worker from "../src/index.js";

const ADMIN_KEY = "local-admin-test-key";

function createEnvironment() {
  const stats = {
    statements: [],
    batches: [],
    runs: [],
    firstCalls: [],
    allCalls: []
  };

  const DB = {
    prepare(sql) {
      const item = {
        sql: sql.replace(/\s+/g, " ").trim(),
        args: []
      };

      stats.statements.push(item);

      return {
        __item: item,

        bind(...args) {
          item.args = args;
          return this;
        },

        async first() {
          stats.firstCalls.push(item);

          if (item.sql.includes("COUNT(*) AS total")) {
            return { total: 2 };
          }

          if (item.sql.includes("FROM stream_sources")) {
            return { id: "source-1", status: "active" };
          }

          return null;
        },

        async all() {
          stats.allCalls.push(item);

          if (item.sql.includes("COUNT(*) AS total")) {
            return { total: 2 };
          }

          if (item.sql.includes("FROM members")) {
            return {
              results: [
                { id: "member-1" },
                { id: "member-2" }
              ]
            };
          }

          return { results: [] };
        },

        async run() {
          stats.runs.push(item);
          return { success: true };
        }
      };
    },

    async batch(statements) {
      stats.batches.push(statements.map(x => x.__item));
      return statements.map(() => ({ success: true }));
    }
  };

  return {
    env: {
      ADMIN_API_KEY: ADMIN_KEY,
      DB
    },
    stats
  };
}

async function adminRequest(path, method, body) {
  const { env, stats } = createEnvironment();

  const response = await worker.fetch(
    new Request(`https://worker.example${path}`, {
      method,
      headers: {
        Authorization: `Bearer ${ADMIN_KEY}`,
        "Content-Type": "application/json"
      },
      body: body === undefined ? undefined : JSON.stringify(body)
    }),
    env
  );

  return {
    response,
    data: await response.json(),
    stats
  };
}

test("Tüm üyelere yayın başlatılabilir", async () => {
  const result = await adminRequest(
    "/admin/broadcast/start",
    "POST",
    {
      title: "Test yayını",
      stream_id: "source-1",
      audience: "all"
    }
  );

  assert.equal(result.response.status, 201);
  assert.equal(result.data.ok, true);
  assert.equal(result.data.audience, "all");
  assert.equal(result.stats.batches.length, 1);

  const sql = result.stats.batches[0]
    .map(x => x.sql)
    .join(" ");

  assert.match(sql, /INSERT INTO broadcasts/);
  assert.match(sql, /INSERT INTO broadcast_recipients/);
  assert.match(sql, /FROM members WHERE status = 'active'/);
  assert.equal(result.data.recipient_count, "all-active-members");
});

test("Seçilmiş aktif üyelere ayrı alıcı kayıtları oluşturulur", async () => {
  const result = await adminRequest(
    "/admin/broadcast/start",
    "POST",
    {
      title: "Seçili yayın",
      stream_id: "source-1",
      audience: "selected",
      member_ids: ["member-1", "member-2", "member-1"]
    }
  );

  assert.equal(result.response.status, 201);
  assert.equal(result.data.recipient_count, 2);

  const batch = result.stats.batches[0];

  assert.equal(batch.length, 3);

  const recipientSql = batch
    .filter(x => x.sql.includes("INSERT INTO broadcast_recipients"));

  assert.equal(recipientSql.length, 2);

  const ids = recipientSql.map(x => x.args[2]).sort();

  assert.deepEqual(ids, ["member-1", "member-2"]);
});

test("Boş alıcı listesiyle seçilmiş yayın başlatılamaz", async () => {
  const result = await adminRequest(
    "/admin/broadcast/start",
    "POST",
    {
      title: "Geçersiz yayın",
      stream_id: "source-1",
      audience: "selected",
      member_ids: []
    }
  );

  assert.equal(result.response.status, 400);
  assert.equal(result.stats.batches.length, 0);
});

test("Yayın durdurulunca oturumlar ve alıcılar iptal edilir", async () => {
  const result = await adminRequest(
    "/admin/broadcast/stop",
    "POST",
    {
      broadcast_id: "broadcast-1"
    }
  );

  assert.equal(result.response.status, 200);
  assert.equal(result.data.ok, true);

  const statements = result.stats.runs.map(x => x.sql);

  assert.ok(statements.some(sql =>
    sql.includes("UPDATE broadcasts") &&
    sql.includes("status = 'stopped'")
  ));

  assert.ok(statements.some(sql =>
    sql.includes("UPDATE playback_sessions") &&
    sql.includes("status = 'revoked'") &&
    sql.includes("broadcast_id = ?")
  ));

  assert.ok(statements.some(sql =>
    sql.includes("UPDATE broadcast_recipients") &&
    sql.includes("status = 'ended'")
  ));
});

test("Cihaz engellendiğinde cihazın yayın oturumları iptal edilir", async () => {
  const result = await adminRequest(
    "/admin/devices/device-record-1/status",
    "PATCH",
    {
      status: "blocked"
    }
  );

  assert.equal(result.response.status, 200);

  const statements = result.stats.runs.map(x => x.sql);

  assert.ok(statements.some(sql =>
    sql.includes("UPDATE devices") &&
    sql.includes("status = ?")
  ));

  assert.ok(statements.some(sql =>
    sql.includes("UPDATE playback_sessions") &&
    sql.includes("status = 'revoked'")
  ));
});

test("Yayın durdurma isteğinde kimlik yoksa işlem yapılmaz", async () => {
  const result = await adminRequest(
    "/admin/broadcast/stop",
    "POST",
    {}
  );

  assert.equal(result.response.status, 400);
  assert.equal(result.stats.runs.length, 0);
});
