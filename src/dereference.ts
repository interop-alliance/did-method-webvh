/**
 * Verification-method DID URL dereference over an already-loaded log.
 *
 * A `did:webvh` DID URL may carry the `versionId` DID parameter and a
 * fragment: `did:webvh:<scid>:<host>?versionId=<id>#<fragment>` names the
 * verification method `<fragment>` in the DID document at that version.
 * This module is pure. It reads the log it is given and does no network
 * request and no verification. The caller verifies the log first.
 *
 * The member is looked up as `<document id>#<fragment>`, not as
 * `<url did>#<fragment>`. A portable DID that moved carries its earlier
 * versions under the earlier DID, and a URL naming the current DID must still
 * reach the members of those versions.
 */
import { findVerificationMethod } from './did-document.js';
import type { DIDLog, VerificationMethod } from './interfaces.js';

/**
 * The parts of a did:webvh verification-method DID URL:
 * `did:webvh:<scid>:<host>[?versionId=<id>]#<fragment>`.
 *
 * `did` is everything before the first `?` or `#`. `fragment` is everything
 * after the `#`, or `undefined` when the URL has none. Only the `versionId`
 * DID parameter is supported. Any other query parameter throws, as does a
 * repeated, valueless, or empty `versionId`, and an empty query. Answering
 * from a different version than the one asked for would be wrong. The DID
 * itself is not validated here.
 */
export function parseVerificationMethodUrl(didUrl: string): { did: string; versionId?: string; fragment?: string } {
  const hashIndex = didUrl.indexOf('#');
  const beforeFragment = hashIndex === -1 ? didUrl : didUrl.slice(0, hashIndex);
  const fragment = hashIndex === -1 ? undefined : didUrl.slice(hashIndex + 1);

  const queryIndex = beforeFragment.indexOf('?');
  const did = queryIndex === -1 ? beforeFragment : beforeFragment.slice(0, queryIndex);

  let versionId: string | undefined;
  if (queryIndex !== -1) {
    const params = new URLSearchParams(beforeFragment.slice(queryIndex + 1));
    for (const name of params.keys()) {
      if (name !== 'versionId') {
        throw new Error(`Unsupported DID parameter '${name}' in verification method URL ${didUrl}`);
      }
    }
    const versionIds = params.getAll('versionId');
    if (versionIds.length > 1) {
      throw new Error(`Repeated DID parameter 'versionId' in verification method URL ${didUrl}`);
    }
    if (versionIds.length === 0) {
      throw new Error(`Empty query in verification method URL ${didUrl}`);
    }
    if (versionIds[0] === '') {
      throw new Error(`Empty DID parameter 'versionId' in verification method URL ${didUrl}`);
    }
    versionId = versionIds[0];
  }

  return { did, versionId, fragment };
}

/**
 * Dereferences a verification-method DID URL against an already-loaded log.
 * Returns the member `<document id>#<fragment>` of the document at
 * `?versionId=`, or of the latest entry's document when the parameter is
 * absent. Returns `null` when the version does not exist, the URL has no
 * fragment, or the document has no such member. See the module doc for the
 * verification contract.
 */
export function dereferenceVerificationMethod(log: DIDLog, didUrl: string): VerificationMethod | null {
  const { versionId, fragment } = parseVerificationMethodUrl(didUrl);
  const entry = versionId === undefined ? log[log.length - 1] : log.find((e) => e.versionId === versionId);
  if (!entry || fragment === undefined) {
    return null;
  }
  return findVerificationMethod(entry.state, `${entry.state.id}#${fragment}`);
}
