/* auto-generated by NAPI-RS */
/* eslint-disable */
export declare class AsyncEntry {
  /**
   * Create an entry for the given service and username.
   *
   * The default credential builder is used.
   */
  constructor(service: string, username: string)
  /**
   * Create an entry for the given target, service, and username.
   *
   * The default credential builder is used.
   */
  static withTarget(target: string, service: string, username: string): AsyncEntry
  /**
   * Set the password for this entry.
   *
   * Can return an [Ambiguous](Error::Ambiguous) error
   * if there is more than one platform credential
   * that matches this entry.  This can only happen
   * on some platforms, and then only if a third-party
   * application wrote the ambiguous credential.
   */
  setPassword(password: string, signal?: AbortSignal | undefined | null): Promise<void>
  /**
   * Retrieve the password saved for this entry.
   *
   * Returns a [NoEntry](Error::NoEntry) error if there isn't one.
   *
   * Can return an [Ambiguous](Error::Ambiguous) error
   * if there is more than one platform credential
   * that matches this entry.  This can only happen
   * on some platforms, and then only if a third-party
   * application wrote the ambiguous credential.
   */
  getPassword(signal?: AbortSignal | undefined | null): Promise<string | undefined>
  /**
   * Delete the underlying credential for this entry.
   *
   * Returns a [NoEntry](Error::NoEntry) error if there isn't one.
   *
   * Can return an [Ambiguous](Error::Ambiguous) error
   * if there is more than one platform credential
   * that matches this entry.  This can only happen
   * on some platforms, and then only if a third-party
   * application wrote the ambiguous credential.
   *
   * Note: This does _not_ affect the lifetime of the [Entry]
   * structure, which is controlled by Rust.  It only
   * affects the underlying credential store.
   */
  deleteCredential(signal?: AbortSignal | undefined | null): Promise<boolean>
  /** Alias for `deleteCredential` */
  deletePassword(signal?: AbortSignal | undefined | null): Promise<unknown>
}

export declare class Entry {
  /**
   * Create an entry for the given service and username.
   *
   * The default credential builder is used.
   */
  constructor(service: string, username: string)
  /**
   * Create an entry for the given target, service, and username.
   *
   * The default credential builder is used.
   */
  static withTarget(target: string, service: string, username: string): Entry
  /**
   * Set the password for this entry.
   *
   * Can return an [Ambiguous](Error::Ambiguous) error
   * if there is more than one platform credential
   * that matches this entry.  This can only happen
   * on some platforms, and then only if a third-party
   * application wrote the ambiguous credential.
   */
  setPassword(password: string): void
  /**
   * Retrieve the password saved for this entry.
   *
   * Returns a [NoEntry](Error::NoEntry) error if there isn't one.
   *
   * Can return an [Ambiguous](Error::Ambiguous) error
   * if there is more than one platform credential
   * that matches this entry.  This can only happen
   * on some platforms, and then only if a third-party
   * application wrote the ambiguous credential.
   */
  getPassword(): string | null
  /**
   * Delete the underlying credential for this entry.
   *
   * Returns a [NoEntry](Error::NoEntry) error if there isn't one.
   *
   * Can return an [Ambiguous](Error::Ambiguous) error
   * if there is more than one platform credential
   * that matches this entry.  This can only happen
   * on some platforms, and then only if a third-party
   * application wrote the ambiguous credential.
   *
   * Note: This does _not_ affect the lifetime of the [Entry]
   * structure, which is controlled by Rust.  It only
   * affects the underlying credential store.
   */
  deleteCredential(): boolean
  /** Alias for `deleteCredential` */
  deletePassword(): boolean
}

export interface Credential {
  account: string
  password: string
}

/** find credentials by service name */
export declare function findCredentials(service: string, target?: string | undefined | null): Array<Credential>

/** find credentials by service name */
export declare function findCredentialsAsync(service: string, target?: string | undefined | null, signal?: AbortSignal | undefined | null): Promise<Array<Credential>>
