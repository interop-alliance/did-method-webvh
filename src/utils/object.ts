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

/**
 * Like {@link replaceValueInObject}, but applies several `[search, replace]`
 * substitutions in a single recursive pass instead of one full tree rebuild
 * per substitution.
 */
export function replaceValuesInObject<T>(obj: T, replacements: ReadonlyArray<readonly [string, string]>): T {
  if (typeof obj === 'string') {
    let result: string = obj;
    for (const [searchValue, replaceValue] of replacements) {
      result = result.replaceAll(searchValue, replaceValue);
    }
    return result as T;
  }
  if (Array.isArray(obj)) {
    return obj.map((item) => replaceValuesInObject(item, replacements)) as T;
  }
  if (obj && typeof obj === 'object') {
    const result: Record<string, unknown> = {};
    for (const [key, value] of Object.entries(obj as Record<string, unknown>)) {
      result[key] = replaceValuesInObject(value, replacements);
    }
    return result as T;
  }
  return obj;
}
