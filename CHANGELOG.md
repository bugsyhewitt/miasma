# Changelog

All notable changes to miasma are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-06-20

### Added
- 35-plugin verifier surface (12 CVE-named + 22 MIASMA-named + 1 test-stub):
  - CVE plugins: cve_2009_3548, cve_2024_23897, cve_2024_55591, cve_2025_0282,
    cve_2025_3248, cve_2025_32975, cve_2025_34028, cve_2025_41243,
    cve_2025_55752, cve_2025_61666, cve_2025_64446, cve_2026_1340.
  - MIASMA plugins: miasma_activemq_001, miasma_actuator_001,
    miasma_cassandra_001, miasma_consul_001, miasma_couchdb_001,
    miasma_docker_001, miasma_elastic_001, miasma_env_001, miasma_etcd_001,
    miasma_git_001, miasma_grafana_001, miasma_influxdb_001,
    miasma_jupyter_001, miasma_k8s_001, miasma_kibana_001,
    miasma_memcached_001, miasma_mongodb_001, miasma_prometheus_001,
    miasma_rabbitmq_001, miasma_redis_001, miasma_solr_001,
    miasma_zookeeper_001.
  - Test-stub plugin: test_always_finds (minimal-shape example).
- CLI surface: `--target` (host/range), `--port-range`, `--plugins` (CSV),
  `--concurrency`, `--list-plugins`, `--version`, `--output-file`.
- Recon pipeline: `miasma.recon.recon(target, port_range)` resolves a target
  into a list of probe candidates using `nmap-wrapper` (declared runtime dep).
- Runner pipeline: `miasma.runner.run_plugins(target, names, concurrency)`
  executes the selected plugins in parallel and returns a list of `Finding`
  objects (or `None` per plugin for no-match).
- JSON finding output: `Finding.to_json()` produces the canonical
  `{cve, severity, confidence, target, evidence, recommendation}` shape.
- Wheel-install contract pinned by `tests/test_wheel_ship_gate.py`:
  `@pytest.mark.ship_gate` builds `--wheel --sdist` via `python -m build`,
  installs into a fresh venv, asserts `miasma --version` = `miasma 1.0.0`,
  asserts `miasma --list-plugins` matches the editable-install output (35 plugins),
  asserts `import miasma; miasma.__version__ == '1.0.0'`, asserts every public
  module + all 35 plugin modules import cleanly from the fresh venv, asserts
  cross-cutting tests pass in the fresh venv (smoke, core, runner, recon,
  applicability, concurrency, output_file).

### Changed
- Version constant bumped from `0.1.0` to `1.0.0` (production-ready release).
- `tests/test_wheel_ship_gate.py::test_wheel_list_plugins`: hardcoded
  `len(installed_stems) == 34` → `== 35` (the live plugin count after
  PRs #35 and #36 added miasma_activemq_001 and miasma_jupyter_001,
  pushing the count past 34). The earlier assertion was a stale ship-count
  pin; the v1.0 release pins the correct count.

[1.0.0]: https://github.com/bugsyhewitt/miasma/releases/tag/v1.0.0
