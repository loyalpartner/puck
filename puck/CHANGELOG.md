# Changelog

## [0.4.3](https://github.com/loyalpartner/puck/compare/v0.4.2...v0.4.3) (2026-08-16)


### Bug Fixes

* **puck:** prefer a dedicated cross-gcc over CC_&lt;target&gt; for the bootstrapper ([f78f014](https://github.com/loyalpartner/puck/commit/f78f014dbd3f0ef23a048c39d5a6350b7f134e62))

## [0.4.2](https://github.com/loyalpartner/puck/compare/v0.4.1...v0.4.2) (2026-08-16)


### Bug Fixes

* **puck:** support cross-compiling x86_64 bootstrapper from non-x86 hosts ([8f0de2c](https://github.com/loyalpartner/puck/commit/8f0de2caaff92841188a8f423a083b22131d2d40))

## [0.4.1](https://github.com/loyalpartner/puck/compare/v0.4.0...v0.4.1) (2026-02-07)


### Bug Fixes

* **puck:** handle injection into undumpable processes ([065c259](https://github.com/loyalpartner/puck/commit/065c2599c6eae449c72525678322a49d0ec50998))
* **puck:** handle injection into undumpable processes (file capabilities) ([e8053a3](https://github.com/loyalpartner/puck/commit/e8053a38cb70daad53f1780a40aa77ba4febcd0e))

## [0.4.0](https://github.com/loyalpartner/puck/compare/v0.3.0...v0.4.0) (2026-01-26)


### Features

* **puck:** add dlopen keyword for better discoverability ([c48d727](https://github.com/loyalpartner/puck/commit/c48d7275c7e8376c036302d3dd7c7f62cdae389b))

## [0.3.0](https://github.com/loyalpartner/puck/compare/v0.2.0...v0.3.0) (2026-01-26)


### Features

* add package metadata for crates.io publishing ([479e047](https://github.com/loyalpartner/puck/commit/479e047c30efb9077c1479e3acf54833de1d4d24))
* **puck:** add keywords and categories for crates.io discoverability ([56ad0fd](https://github.com/loyalpartner/puck/commit/56ad0fd5e8035a41156d1ee19afc4e1c1240f94e))


### Bug Fixes

* **ci:** move bootstrapper into puck package for crates.io publishing ([5eda497](https://github.com/loyalpartner/puck/commit/5eda497a5172a83c96ace81d830d304a6ec5bbc5))
* rename puck package to puck-rs for crates.io ([e314216](https://github.com/loyalpartner/puck/commit/e3142166c4b2a48e070041bb436e8be08c9d772b))

## [0.2.0](https://github.com/loyalpartner/puck/compare/v0.1.0...v0.2.0) (2026-01-26)


### Features

* rename hsinject to puck, add QEMU integration tests ([0dee933](https://github.com/loyalpartner/puck/commit/0dee93310511c68359c861ed965d48b9d189624f))
* **test:** optimize QEMU tests with session-scoped VM ([65b0a7e](https://github.com/loyalpartner/puck/commit/65b0a7ebc2b713b1dd5008785faaa9bb201fa921))


### Bug Fixes

* **aarch64:** fix SIGBUS crash with alignment and syscall instruction ([16c4237](https://github.com/loyalpartner/puck/commit/16c423711a057056c268402b4321c595e686e3db))
* **ci:** use explicit versions in Cargo.toml ([7c6f1bd](https://github.com/loyalpartner/puck/commit/7c6f1bd8b13cdfba76d3856a3f2198074514eb04))
