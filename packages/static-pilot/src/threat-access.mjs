export const ACCESS_SCOPES = ['all', 'external', 'internal', 'mixed', 'unresolved'];

export function actorAccess(actor) {
  if (ACCESS_SCOPES.slice(1).includes(actor.accessClassification))
    return { kind: actor.accessClassification, basis: 'reviewer declaration' };
  // Use explicit actor descriptions only. A network interface, repository or
  // authenticated caller does not establish where the actor starts.
  const name = String(actor.name || '').toLowerCase();
  const external = /\b(external|internet|remote attacker)\b/.test(name);
  const internal = /\b(internal|insider|developer|operator|administrator|compromised (service|workload|worker|process))\b/.test(name);
  return {
    kind: external && internal ? 'mixed' : external ? 'external' : internal ? 'internal' : 'unresolved',
    basis: external || internal ? 'actor description; deployment unverified' : 'initial actor location unresolved',
  };
}

export function threatAccess(threat, actors) {
  const kinds = (threat.actorIds || []).map(id => actors.get(id)?.access?.kind || 'unresolved');
  if (!kinds.length) return {kind: 'unresolved', hasUnresolved: true};
  const external = kinds.includes('external'), internal = kinds.includes('internal');
  return {
    kind: kinds.includes('mixed') || external && internal ? 'mixed' : external ? 'external' : internal ? 'internal' : 'unresolved',
    hasUnresolved: kinds.includes('unresolved'),
  };
}

export function matchesAccess(record, scope = 'all', includeUnresolved = true) {
  const access = record.access || {kind: 'unresolved'};
  return scope === 'all' || access.kind === scope ||
    (['external', 'internal'].includes(scope) && access.kind === 'mixed') ||
    (includeUnresolved && (access.kind === 'unresolved' || access.hasUnresolved));
}

export function accessFilter(scope = 'all', includeUnresolved = true) {
  if (!ACCESS_SCOPES.includes(scope)) throw Error('Invalid actor access filter');
  return {scope, includeUnresolved};
}
