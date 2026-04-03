import type { SessionData, SessionDataStore } from "../../types/index.js";
import {
  CookieOptions,
  ReadonlyRequestCookies,
  RequestCookies,
  ResponseCookies
} from "../cookies.js";

export interface SessionCookieOptions {
  /**
   * The name of the session cookie.
   *
   * Default: `__session`.
   */
  name?: string;
  /**
   * The sameSite attribute of the session cookie.
   *
   * Default: `lax`.
   */
  sameSite?: "strict" | "lax" | "none";
  /**
   * The secure attribute of the session cookie.
   *
   * Default: depends on the protocol of the application's base URL. If the protocol is `https`, then `true`, otherwise `false`.
   */
  secure?: boolean;
  /**
   * The path attribute of the session cookie. Will be set to '/' by default.
   */
  path?: string;
  /**
   * Specifies the value for the {@link https://tools.ietf.org/html/rfc6265#section-5.2.3|Domain Set-Cookie attribute}. By default, no
   * domain is set, and most clients will consider the cookie to apply to only
   * the current domain.
   */
  domain?: string;
  /**
   * The transient attribute of the session cookie. When true, the cookie will not persist beyond the current session.
   */
  transient?: boolean;
}

export interface SessionConfiguration {
  /**
   * A boolean indicating whether rolling sessions should be used or not.
   *
   * When enabled, the session will continue to be extended as long as it is used within the inactivity duration.
   * Once the upper bound, set via the `absoluteDuration`, has been reached, the session will no longer be extended.
   *
   * Default: `true`.
   */
  rolling?: boolean;
  /**
   * The absolute duration after which the session will expire. The value must be specified in seconds.
   *
   * Once the absolute duration has been reached, the session will no longer be extended.
   *
   * Default: 3 days.
   */
  absoluteDuration?: number;
  /**
   * The duration of inactivity after which the session will expire. The value must be specified in seconds.
   *
   * The session will be extended as long as it was active before the inactivity duration has been reached.
   *
   * Default: 1 day.
   */
  inactivityDuration?: number;

  /**
   * The options for the session cookie.
   */
  cookie?: SessionCookieOptions;
}

/**
 * A session secret configuration which allows for key rotation by specifying multiple secrets and indicating which one is currently in use via the `currentKid` property.
 * Example:
 * ```js
 * secret: {
 *   currentKid: "K-1775256242505",
 *   allowedKeys: {
 *     "K-1775256222544": "secretValue1",
 *     "K-1775256242505": "secretValue2"
 *   }
 * }
 * ```
 * In this example, newly encrypted cookies will have the `kid` of "K-1775256242505" and use the secret "secretValue2" for encryption, but cookies with the `kid` of "K-1775256222544" can still be decrypted.
 * After an older-keyed session is decrypted, it will be re-encrypted using the latest key defined by currentKid.
 *
 * When a sufficient number of your users have moved to the new secret, you should remove the old secret from the allowedKeys object.
 * Example:
 * ```js
 * secret: {
 *   currentKid: "K-1775256242505",
 *   allowedKeys: {
 *     "K-1775256242505": "secretValue2"
 *   }
 * }
 * ```
 * With the old secret removed, encrypted sessions using the old secret will no longer be decryptable, and users with those sessions will need to log in again.
 * Knowing when to remove your old key is an individual decision based on risk tolerance, user base, and circumstances. For example, a compromised key may require more urgent action than a simple routine key rotation.
 */
export interface SessionSecretConfig {
  /**
   * The key identifier (`kid`) of the currently used secret. This value is used to indicate which secret in the `allowedKeys` object is currently being used to encrypt new cookies.
   * A `kid` is a public identifier for a secret and will be set into the encrypted session cookie, where it is readable by anyone. A `kid` should be an opaque identifier that helps identify which key was used.
   * One popular approach is to use a unix timestamp as the `kid`, which allows for easy identification of when a secret was put into service, but any unique string can be used.
   */

  currentKid: string;

  /**
   * The key identifier (`kid`) of the fallback secret. This value is used when decrypting/verifying cookies that do not have a `kid`.
   * This allows for a smooth rotation where the new encrypted cookies have a `kid`, but we can still read old cookies without a `kid` until they naturally expire.
   * This value is optional, and if not provided, the `currentKid` will be used as the fallback `kid`. If provided, it must match a key in the `allowedKeys` object.
   *
   * Typically this doesn't need to be provided, since using the `currentKid` as the fallback is usually sufficient. However, if you are migrating to this object structure for the first time
   * and simulateously rotating your secret, you will need to use this property.
   * Example:
   * ```js
   * secret: {
   *   currentKid: "K-SomeIdentifierForNewKey",
   *   fallbackKid: "K-SomeIdentifierForOldKey",
   *   allowedKeys: {
   *     "K-SomeIdentifierForOldKey": "OldSecretValue",
   *     "K-SomeIdentifierForNewKey": "NewSecretValue"
   *   }
   * }
   * ```
   * In this scenario, you MAKE UP a `kid` for the old key, as the SDK was not setting one before.
   * This newly made-up identifier is what you set as the `fallbackKid`, and put your old secret value in the `allowedKeys` object at that same key name. When the SDK encounters an encrypted session without a `kid`,
   * it will use the key identified by the `fallbackKid`.
   */
  fallbackKid?: string;

  /**
   * A record of allowed keys for encryption/decryption. The keys are stored in an object where the key is the `kid` and the value is the secret value used for encryption/decryption.
   * When decrypting/verifying a cookie, the `kid` from the cookie will be used to look up the corresponding secret in this object.
   */

  allowedKeys: Record<string, string>;
}

export type SecretOption = string | SessionSecretConfig;

export interface SessionStoreOptions extends SessionConfiguration {
  secret: SecretOption;
  store?: SessionDataStore;

  cookieOptions?: SessionCookieOptions;
}

const SESSION_COOKIE_NAME = "__session";

export abstract class AbstractSessionStore {
  public secret: SecretOption;
  public sessionCookieName: string;

  private rolling: boolean;
  private absoluteDuration: number;
  private inactivityDuration: number;

  public store?: SessionDataStore;

  public cookieConfig: CookieOptions;

  constructor({
    secret,

    rolling = true,
    absoluteDuration = 60 * 60 * 24 * 3, // 3 days in seconds
    inactivityDuration = 60 * 60 * 24 * 1, // 1 day in seconds
    store,

    cookieOptions
  }: SessionStoreOptions) {
    this.secret = secret;

    this.rolling = rolling;
    this.absoluteDuration = absoluteDuration;
    this.inactivityDuration = inactivityDuration;
    this.store = store;

    this.sessionCookieName = cookieOptions?.name ?? SESSION_COOKIE_NAME;
    this.cookieConfig = {
      httpOnly: true,
      sameSite: cookieOptions?.sameSite ?? "lax",
      secure: cookieOptions?.secure ?? false,
      path: cookieOptions?.path ?? "/",
      domain: cookieOptions?.domain,
      transient: cookieOptions?.transient
    };
  }

  abstract get(
    reqCookies: RequestCookies | ReadonlyRequestCookies
  ): Promise<SessionData | null>;

  /**
   * save adds the encrypted session cookie as a `Set-Cookie` header. If the `iat` property
   * is present on the session, then it will be used to compute the `maxAge` cookie value.
   */
  abstract set(
    reqCookies: RequestCookies | ReadonlyRequestCookies,
    resCookies: ResponseCookies,
    session: SessionData,
    isNew?: boolean
  ): Promise<void>;

  abstract delete(
    reqCookies: RequestCookies | ReadonlyRequestCookies,
    resCookies: ResponseCookies
  ): Promise<void>;

  /**
   * epoch returns the time since unix epoch in seconds.
   */
  epoch() {
    return (Date.now() / 1000) | 0;
  }

  /**
   * calculateMaxAge calculates the max age of the session based on createdAt and the rolling and absolute durations.
   */
  calculateMaxAge(createdAt: number) {
    if (!this.rolling) {
      return this.absoluteDuration;
    }

    const updatedAt = this.epoch();
    const expiresAt = Math.min(
      updatedAt + this.inactivityDuration,
      createdAt + this.absoluteDuration
    );
    // Fix race condition: use the same updatedAt timestamp for consistency
    const maxAge = expiresAt - updatedAt;

    return maxAge > 0 ? maxAge : 0;
  }
}
