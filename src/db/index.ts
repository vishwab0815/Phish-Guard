import { drizzle, type PostgresJsDatabase } from 'drizzle-orm/postgres-js';
import postgres from 'postgres';
import * as schema from './schema';

type Database = PostgresJsDatabase<typeof schema>;
type Client = ReturnType<typeof postgres>;

/**
 * The client is created lazily on first use, so `next build` (which imports
 * route modules) works without DATABASE_URL. In development the client is
 * cached on globalThis so hot reloads don't open a new pool every time.
 */
const globalForDb = globalThis as unknown as {
  __pgClient?: Client;
  __drizzleDb?: Database;
};

let client: Client | undefined;
let instance: Database | undefined;

function getDb(): Database {
  if (instance) return instance;

  if (process.env.NODE_ENV !== 'production' && globalForDb.__drizzleDb) {
    client = globalForDb.__pgClient;
    instance = globalForDb.__drizzleDb;
    return instance;
  }

  const connectionString = process.env.DATABASE_URL;
  if (!connectionString) {
    throw new Error(
      'DATABASE_URL is not set. Copy .env.example to .env.local and add your Postgres connection string.'
    );
  }

  // max: 5 keeps serverless instances from exhausting the pooler.
  // prepare: false is required for transaction-mode poolers (Supabase/PgBouncer).
  client = postgres(connectionString, { prepare: false, max: 5, connect_timeout: 5 });
  instance = drizzle(client, { schema });

  if (process.env.NODE_ENV !== 'production') {
    globalForDb.__pgClient = client;
    globalForDb.__drizzleDb = instance;
  }
  return instance;
}

export const db: Database = new Proxy({} as Database, {
  get(_target, prop) {
    const real = getDb();
    const value = Reflect.get(real, prop, real);
    return typeof value === 'function' ? value.bind(real) : value;
  },
});

/** Close the connection pool (used by scripts such as the seed so the process can exit). */
export async function closeDb(): Promise<void> {
  const c = client ?? globalForDb.__pgClient;
  client = undefined;
  instance = undefined;
  globalForDb.__pgClient = undefined;
  globalForDb.__drizzleDb = undefined;
  if (c) await c.end({ timeout: 5 });
}
