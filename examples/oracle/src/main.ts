import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { createApplication, KitError } from '@arkenivajs/core';
import type { SqlProvider } from '@arkenivajs/core';
import { oraclePlugin } from '@arkenivajs/database-oracle';

/** Read a NUMBER(38,0) as an exact string DTO, without a lossy number conversion. */
export async function readOracleExact(sql: Pick<SqlProvider, 'queryOne'>, value: bigint) {
  if (typeof value !== 'bigint' || value.toString().replace('-', '').length > 38)
    throw new KitError({
      code: 'EK_CONFIG_INVALID',
      message: 'The Oracle example requires an integer with at most 38 digits',
    });
  const row = await sql.queryOne<{ exact: string }>('legacy', {
    text: 'SELECT CAST(:value AS NUMBER(38,0)) AS "exact" FROM DUAL',
    bindings: { value },
  });
  if (!row || typeof row.exact !== 'string' || !/^-?\d+(?![\s\S])/.test(row.exact))
    throw new KitError({
      code: 'EK_DATABASE_QUERY',
      message: 'Oracle did not return the expected exact integer text',
    });
  return Object.freeze({ exact: row.exact });
}

/** Explicit live opt-in is required; ordinary documentation tests use the typed SQL boundary. */
export async function runOracleExample() {
  if (process.env.ARKENIVA_ORACLE_LIVE !== '1')
    throw new KitError({
      code: 'EK_CONFIG_INVALID',
      message: 'The Oracle example requires explicit live opt-in',
    });
  if (!process.env.ARKENIVA_ORACLE_URL)
    throw new KitError({ code: 'EK_CONFIG_MISSING', message: 'ARKENIVA_ORACLE_URL is required' });
  const app = await createApplication({
    service: { name: 'oracle-exact-example', version: '1.0.0', environment: 'development' },
    plugins: [oraclePlugin()],
    databases: {
      legacy: { driver: 'oracle', connectionStringEnv: 'ARKENIVA_ORACLE_URL', poolMax: 2 },
    },
  });
  try {
    await app.start();
    return await readOracleExact(app.sql, 9007199254740993n);
  } finally {
    await app.stop();
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  try {
    console.log(JSON.stringify(await runOracleExample()));
  } catch (error) {
    console.error(
      JSON.stringify(
        error instanceof KitError
          ? error.toSafeJSON()
          : { code: 'EK_INTERNAL', message: 'The Oracle example failed' },
      ),
    );
    process.exitCode = 1;
  }
}
