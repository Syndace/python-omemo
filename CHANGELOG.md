# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed
- CHANGED EVERYTHING!!!
- Complete rewrite of the whole library (and dependencies) to use asynchronous and (strictly) typed Python 3.
- Built-in support for [XEP-0384](https://xmpp.org/extensions/xep-0384.html) >= 0.4 in the namespace `urn:xmpp:omemo:1`. Legacy OMEMO in the namespace `eu.siacs.conversations.axolotl` remains available in the [python-omemo-backend-legacy](https://github.com/Syndace/python-omemo-backend-legacy) package.
- Mostly following [Keep a Changelog](https://keepachangelog.com/en/1.0.0/) now (except for the date format).
- Compatibility with the old serialization format is preserved!

## [0.14.0] - Unreleased

### Changed
- Adjusted signature of the `SessionManager.encryptRatchetForwardingMessage` method to accept exactly one bare JID + device id pair
- Updated the license in the setup.py, which was desync with the LICENSE file
- Adjusted the copyright year

### Removed
- Removed Python 3.4 from the list of supported Python versions
- Removed some mentions of Python 2 from the README

## [0.13.0] - 15th of December 2021

### Added
- Added a method to retrieve the receiving chain length of a single session form the `SessionManager`

### Changed
- The storage interface has been modified to use asyncio coroutines instead of callbacks.
- All methods of the session manager that returned promises previously have been replaced with equivalent asyncio coroutines.

### Removed
- Dropped Python 2 support and removed a bit of Python 2 compatibility clutter
- Removed synchronous APIs
- Removed thread-based promise implementation in favor of asyncio futures and coroutines

## [0.12.0] - 28th of March, 2020

### Changed
- The `JSONFileStorage` now encodes JIDs using hashes, to avoid various issues regarding the file system. **WARNING, THERE ARE KNOWN ISSUES WITH THIS VERSION OF THE STORAGE IMPLEMENTATION.**
- Sending 12 byte IVs instead of 16 now.
- `SessionManager.encryptKeyTransportMessage` now receives the optional plaintext as a parameter directly, instead of using a callback to encrypt external data. If the plaintext is omitted, a shared secret is returned that can be used for purposes external to this library.
- Switched to MIT license with the agreement of all contributors!

### Fixed
- Fixed the way key transport messages are sent and received to be compatible with other implementations.

## [0.11.0] - 13th of December, 2019

### Added
- Added a new method `resetTrust`, which allows going back to the trust level `undecided`.

### Changed
- Merged the `trust` and `distrust` methods into `setTrust`.
- `Storage.storeTrust` must now be able to handle the value `None` for the `trust` parameter.

### Removed
- Removed the `SessionManagerAsyncIO`, in preparation for the big Python 3 update coming soon™.

### Fixed
- Fixed a bug in the `SessionManager`, where the contents of a parameter (passed by reference) were modified.

## [0.10.5] - 21st of July, 2019

### Fixed
- Fixed two bugs in the `JSONFileStorage` implementation.
- Fixed a type issue in the `__str__` of the `TrustException`.
- Fixed a rare bug where sessions uncapable of encrypting messages would be stored.

## [0.10.4] - 1st of February, 2019

### Added
- Added an implementation of the storage using a simple directory structure and JSON files.

### Changed
- `RatchetForwardingMessages` do not require the recipient to be trusted any more, as they contain no user-generated content. See #22 for information.
- Renamed `UntrustedException` to `TrustException` and added a fourth field `problem` to get the type of problem (untrusted vs. undecided).

## [0.10.3] - 29th of December, 2018

### Added
- Added a method for requesting trust information from the storage at bulk. This can be overridden for better performance.
- Added a method for requesting sessions from the storage at bulk. This can be overridden for better performance.
- Added a public method to delete an existing session. This is useful to recover from broken sessions.
- Added a public method to retrieve a list of all managed JIDs.
- Added a stresstest, mostly to test recursion depth.

### Changed
- Turned the changelog upside-down, so that the first entry is the newest.
- Modified `no_coroutine` in the promise lib to use a loop instead of recursion.
- Modified the promise constructor to run promises in threads.

## [0.10.2] - 29th of December, 2018

### Added
- Added methods to retrieve trust information from the `SessionManager`: `getTrustForDevice` and `getTrustForJID`.

### Changed
- Introduced an exception hierarchy to allow for more fine-grained exception catching and type checking.
- Most exceptions now implement `__str__` to generate human-readable messages.

### Fixed
- Fixed a bug that tried to instantiate an object of the wrong class from serialized data.

## [0.10.1] - 27th of December, 2018

### Added
- Added CHANGELOG.

### Changed
- Upon serialization the current library version is added to the serialized structures, to allow for seamless updates in the future.

[Unreleased]: https://github.com/Syndace/python-omemo/compare/v0.14.0...HEAD
[0.14.0]: https://github.com/Syndace/python-omemo/compare/v0.13.0...v0.14.0
[0.13.0]: https://github.com/Syndace/python-omemo/compare/v0.12.0...v0.13.0
[0.12.0]: https://github.com/Syndace/python-omemo/compare/v0.11.0...v0.12.0
[0.11.0]: https://github.com/Syndace/python-omemo/compare/v0.10.5...v0.11.0
[0.10.5]: https://github.com/Syndace/python-omemo/compare/v0.10.4...v0.10.5
[0.10.4]: https://github.com/Syndace/python-omemo/compare/v0.10.3...v0.10.4
[0.10.3]: https://github.com/Syndace/python-omemo/compare/v0.10.2...v0.10.3
[0.10.2]: https://github.com/Syndace/python-omemo/compare/v0.10.1...v0.10.2
[0.10.1]: https://github.com/Syndace/python-omemo/releases/tag/v0.10.1
