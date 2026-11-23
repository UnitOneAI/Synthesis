import { parseXml } from './inventory.mjs';
import { sha, id } from './sources.mjs';
// Import declarations only. Raw configuration values (including credentials)
// are never persisted, sent to the model, or used to contact a target.
const AREAS = { Authentication: 'caller', Authorization: 'caller', ConnectionStrings: 'data', RabbitMQ: 'data', GraphDB: 'data', SqlDatabase: 'data', ServiceInstall: 'execution', ServiceConfig: 'execution', Permission: 'execution', PermissionEx: 'execution', Certificate: 'transport', binding: 'exposure', endpoint: 'exposure', AllowedHosts: 'exposure', Kestrel: 'exposure', ReverseProxy: 'exposure' };
export function deploymentArtifact(input) {
  if (typeof input.text !== 'string' || Buffer.byteLength(input.text) > 256 * 1024) throw Error('Configuration import must be at most 256 KiB');
  if (!/\.(json|xml|config|wxs|wxi)$/i.test(input.name || '')) throw Error('Choose JSON or XML configuration; scripts are not imported');
  let value;
  try { value = /\.json$/i.test(input.name) ? JSON.parse(input.text) : parseXml(input.text); }
  catch { throw Error('Configuration could not be parsed; no content was saved'); }
  const declarations = new Map(); let visited = 0;
  function visit(node, depth = 0) {
    if (++visited > 8000 || depth > 30) throw Error('Configuration nesting or declaration limit reached');
    if (!node || typeof node !== 'object') return;
    for (const [key, child] of Object.entries(node)) {
      if (Object.hasOwn(AREAS, key)) declarations.set(key, { key, area: AREAS[key], basis: 'operator-provided configuration declaration; values not retained' });
      visit(child, depth + 1);
    }
  }
  visit(value);
  if (!declarations.size) throw Error('No supported deployment declarations found; no content was saved');
  const hash = sha(input.text);
  return { id: id('deployment-artifact', hash), name: 'Imported configuration ' + hash.slice(0, 8), sha256: hash, declarations: [...declarations.values()], interpretation: 'Raw configuration not retained. Declaration presence does not establish effective settings or deployed state.' };
}
