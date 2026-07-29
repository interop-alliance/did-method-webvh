/**
 * Leaf module for plain-object helpers. It must not import from `../utils.js`
 * or `../did-document.js` so that both can depend on it without forming an
 * import cycle.
 */

/**
 * Recursively replaces every occurrence of `searchValue` with `replaceValue`
 * in all string values (and string array items) reachable from `obj`. Returns
 * a structurally-cloned copy; the input is not mutated.
 */
export function replaceValueInObject<T>(obj: T, searchValue: string, replaceValue: string): T {
  if (typeof obj === 'string') {
    return obj.replaceAll(searchValue, replaceValue) as T;
  }
  if (Array.isArray(obj)) {
    return obj.map((item) => replaceValueInObject(item, searchValue, replaceValue)) as T;
  }
  if (obj && typeof obj === 'object') {
    const result: Record<string, unknown> = {};
    for (const [key, value] of Object.entries(obj as Record<string, unknown>)) {
      result[key] = replaceValueInObject(value, searchValue, replaceValue);
    }
    return result as T;
  }
  return obj;
}
