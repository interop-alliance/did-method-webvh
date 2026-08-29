import { canonicalizeEx } from 'json-canonicalize';

/**
 * `ancestors` holds the objects on the CURRENT recursion path, not every
 * object visited: an input that reaches the same object or array from two
 * places -- one instance referenced twice, not two equal copies -- is an
 * ordinary acyclic graph (a signed zcap whose proof carries the same
 * `@context` array instance as the document is one), and canonicalizes to the
 * same bytes as its JSON round trip. Only a value containing itself is
 * circular, so each object leaves the set as its subtree finishes.
 */
const sanitizeForCanonicalization = (value: unknown, ancestors: WeakSet<object>): unknown => {
  if (value === null) return null;

  const type = typeof value;
  if (type === 'undefined') {
    throw new Error('Canonicalization input contains undefined in array position');
  }
  if (type === 'function' || type === 'symbol' || type === 'bigint') {
    throw new Error(`Canonicalization input contains unsupported type: ${type}`);
  }
  if (type === 'number' && !Number.isFinite(value as number)) {
    throw new Error('Canonicalization input contains non-finite number');
  }
  if (type !== 'object') return value;

  const obj = value as Record<string, unknown>;
  if (ancestors.has(obj)) {
    throw new Error('Canonicalization input contains circular references');
  }
  ancestors.add(obj);

  if (Array.isArray(obj)) {
    const sanitizedArray: unknown[] = [];
    for (const item of obj) {
      sanitizedArray.push(sanitizeForCanonicalization(item, ancestors));
    }
    ancestors.delete(obj);
    return sanitizedArray;
  }

  const sanitizedObject: Record<string, unknown> = {};
  for (const [key, entry] of Object.entries(obj)) {
    if (typeof entry === 'undefined') {
      continue;
    }
    sanitizedObject[key] = sanitizeForCanonicalization(entry, ancestors);
  }
  ancestors.delete(obj);
  return sanitizedObject;
};

export const canonicalizeStrict = (value: unknown): string => {
  const sanitized = sanitizeForCanonicalization(value, new WeakSet<object>());
  return canonicalizeEx(sanitized, {
    allowCircular: false,
    filterUndefined: true,
    undefinedInArrayToNull: false,
  });
};
