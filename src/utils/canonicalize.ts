import { canonicalizeEx } from 'json-canonicalize';

const sanitizeForCanonicalization = (value: unknown, seen: WeakMap<object, unknown>): unknown => {
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
  if (seen.has(obj)) {
    throw new Error('Canonicalization input contains circular references');
  }

  if (Array.isArray(obj)) {
    const sanitizedArray: unknown[] = [];
    seen.set(obj, sanitizedArray);
    for (const item of obj) {
      sanitizedArray.push(sanitizeForCanonicalization(item, seen));
    }
    return sanitizedArray;
  }

  const sanitizedObject: Record<string, unknown> = {};
  seen.set(obj, sanitizedObject);
  for (const [key, entry] of Object.entries(obj)) {
    if (typeof entry === 'undefined') {
      continue;
    }
    sanitizedObject[key] = sanitizeForCanonicalization(entry, seen);
  }
  return sanitizedObject;
};

export const canonicalizeStrict = (value: unknown): string => {
  const sanitized = sanitizeForCanonicalization(value, new WeakMap<object, unknown>());
  return canonicalizeEx(sanitized, {
    allowCircular: false,
    filterUndefined: true,
    undefinedInArrayToNull: false,
  });
};
