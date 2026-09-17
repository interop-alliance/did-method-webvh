/**
 * Leaf module for plain-object helpers. It must not import from `../utils.js`
 * or `../did-document.js` so that both can depend on it without forming an
 * import cycle.
 */

/**
 * Recursively rebuilds `obj`, applying `transform` to every string it reaches
 * (including string items inside arrays); other leaves are returned as-is.
 * Returns a fresh structure, so the input is not mutated. This is the single
 * tree walk the rest of this module is built on -- callers that need a
 * different per-string rule should pass it here rather than re-deriving the
 * recursion.
 */
export function mapStringsInObject<T>(obj: T, transform: (value: string) => string): T {
  if (typeof obj === 'string') {
    return transform(obj) as T;
  }
  if (Array.isArray(obj)) {
    return obj.map((item) => mapStringsInObject(item, transform)) as T;
  }
  if (obj && typeof obj === 'object') {
    const result: Record<string, unknown> = {};
    for (const [key, value] of Object.entries(obj as Record<string, unknown>)) {
      result[key] = mapStringsInObject(value, transform);
    }
    return result as T;
  }
  return obj;
}

/**
 * Recursively replaces every occurrence of `searchValue` with `replaceValue`
 * in all string values (and string array items) reachable from `obj`. Returns
 * a structurally-cloned copy; the input is not mutated.
 */
export function replaceValueInObject<T>(obj: T, searchValue: string, replaceValue: string): T {
  return mapStringsInObject(obj, (value) => value.replaceAll(searchValue, replaceValue));
}

/**
 * Like {@link replaceValueInObject}, but applies several `[search, replace]`
 * substitutions in a single recursive pass instead of one full tree rebuild
 * per substitution.
 */
export function replaceValuesInObject<T>(obj: T, replacements: ReadonlyArray<readonly [string, string]>): T {
  return mapStringsInObject(obj, (value) => {
    let result = value;
    for (const [searchValue, replaceValue] of replacements) {
      result = result.replaceAll(searchValue, replaceValue);
    }
    return result;
  });
}
