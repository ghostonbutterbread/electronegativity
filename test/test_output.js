import fs from 'fs';
import os from 'os';
import path from 'path';

import run from '../src/runner';
import { buildFindings, buildInventory, buildRunMetadata, buildSarifDocument, writeOutputDirectory } from '../src/output';
import { createVersionContext } from '../src/util/electron_context';
import { writeIssues } from '../src/util';
import { findOldestElectronVersionWithSource } from '../src/util/electron_version';

function waitForFile(filename) {
  return new Promise((resolve, reject) => {
    const deadline = Date.now() + 1000;
    function check() {
      fs.readFile(filename, 'utf8', (err, body) => {
        if (!err && body.length > 0)
          return resolve(body);
        if (Date.now() > deadline)
          return reject(err || new Error(`Timed out waiting for ${filename}`));
        setTimeout(check, 10);
      });
    }
    check();
  });
}

let chai = require('chai');
let should = chai.should();

function parseJson(file) {
  return JSON.parse(fs.readFileSync(file, 'utf8'));
}

function parseJsonl(file) {
  const body = fs.readFileSync(file, 'utf8').trim();
  return body ? body.split('\n').map(line => JSON.parse(line)) : [];
}

describe('Structured output', () => {
  const findingFixture = path.resolve('test/checks/AtomicChecks/NODE_INTEGRATION_JS_CHECK_13_1.js');
  const brokenFixture = path.resolve('test/file_formats/broken.js');
  const nodeIntegrationOnly = ['nodeintegrationjscheck'];

  async function runFixture(input, options = {}) {
    return run(Object.assign({
      input,
      customScan: [],
      excludeFromScan: []
    }, options));
  }

  it('returns deterministic schema v1 finding IDs across repeated runs', async function () {
    this.timeout(10000);

    const first = await runFixture(findingFixture, { customScan: nodeIntegrationOnly });
    const second = await runFixture(findingFixture, { customScan: nodeIntegrationOnly });

    first.issues.length.should.be.above(0);
    should.exist(first.schemaV1);
    first.schemaV1.findings.length.should.equal(first.issues.length);
    first.schemaV1.findings.map(finding => finding.result_id).should.deep.equal(second.schemaV1.findings.map(finding => finding.result_id));
    first.schemaV1.findings[0].file.should.equal('NODE_INTEGRATION_JS_CHECK_13_1.js');
    first.schemaV1.findings[0].check_id.should.equal(first.issues[0].id);
  });

  it('writes schema v1 artifacts to an output directory without breaking legacy output', async function () {
    this.timeout(10000);

    const outputRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'electro-structured-output-'));
    const outputDir = path.join(outputRoot, 'audit-out');
    const legacyOutput = path.join(outputRoot, 'results.csv');
    const result = await runFixture(findingFixture, {
      customScan: nodeIntegrationOnly,
      output: legacyOutput,
      outputDir,
      targetId: 'fixture-target'
    });

    fs.existsSync(legacyOutput).should.equal(true);
    fs.existsSync(path.join(outputDir, 'run.json')).should.equal(true);
    fs.existsSync(path.join(outputDir, 'findings.json')).should.equal(true);
    fs.existsSync(path.join(outputDir, 'findings.sarif')).should.equal(true);
    fs.existsSync(path.join(outputDir, 'inventory.json')).should.equal(true);
    fs.existsSync(path.join(outputDir, 'hypotheses.jsonl')).should.equal(true);
    fs.existsSync(path.join(outputDir, 'parse_errors.jsonl')).should.equal(true);
    fs.existsSync(path.join(outputDir, 'summary.md')).should.equal(true);
    fs.existsSync(path.join(outputDir, 'electron-team-context.json')).should.equal(true);

    const runDoc = parseJson(path.join(outputDir, 'run.json'));
    const findingsDoc = parseJson(path.join(outputDir, 'findings.json'));
    const sarifDoc = parseJson(path.join(outputDir, 'findings.sarif'));
    const inventoryDoc = parseJson(path.join(outputDir, 'inventory.json'));
    const contextDoc = parseJson(path.join(outputDir, 'electron-team-context.json'));

    runDoc.schema_version.should.equal('1.0');
    runDoc.target_id.should.equal('fixture-target');
    findingsDoc.findings.map(finding => finding.result_id).should.deep.equal(result.schemaV1.findings.map(finding => finding.result_id));
    sarifDoc.runs[0].results[0].partialFingerprints.resultId.should.equal(result.schemaV1.findings[0].result_id);
    inventoryDoc.records.length.should.be.above(0);
    inventoryDoc.records[0].classification.should.equal('inventory');
    contextDoc.artifact_files.findings.should.equal('findings.json');
    parseJsonl(path.join(outputDir, 'hypotheses.jsonl')).length.should.equal(0);
    parseJsonl(path.join(outputDir, 'parse_errors.jsonl')).length.should.equal(0);
  });

  it('preserves legacy relative SARIF invocation metadata in the structured output directory', async function () {
    this.timeout(10000);

    const outputRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'electro-structured-relative-'));
    const outputDir = path.join(outputRoot, 'audit-out');
    const legacyOutput = path.join(outputRoot, 'legacy.sarif');
    const result = await runFixture(findingFixture, {
      customScan: nodeIntegrationOnly,
      outputDir,
      isRelative: true
    });

    writeIssues(findingFixture, true, legacyOutput, result.issues, true);
    await waitForFile(legacyOutput);
    const sarifDoc = parseJson(path.join(outputDir, 'findings.sarif'));
    const legacySarifDoc = parseJson(legacyOutput);

    sarifDoc.runs[0].invocations.should.deep.equal(legacySarifDoc.runs[0].invocations);
    sarifDoc.runs[0].results[0].locations[0].physicalLocation.artifactLocation.uri.should.equal(legacySarifDoc.runs[0].results[0].locations[0].physicalLocation.artifactLocation.uri);
  });

  it('preserves legacy non-relative SARIF artifact locations in the structured output directory', async function () {
    this.timeout(20000);

    const outputRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'electro-structured-absolute-'));
    const outputDir = path.join(outputRoot, 'audit-out');
    const legacyOutput = path.join(outputRoot, 'legacy.sarif');
    const result = await runFixture(findingFixture, {
      customScan: nodeIntegrationOnly,
      outputDir
    });

    writeIssues(findingFixture, false, legacyOutput, result.issues, true);
    await waitForFile(legacyOutput);
    const sarifDoc = parseJson(path.join(outputDir, 'findings.sarif'));
    const legacySarifDoc = parseJson(legacyOutput);

    sarifDoc.runs[0].results[0].locations[0].physicalLocation.artifactLocation.uri.should.equal(legacySarifDoc.runs[0].results[0].locations[0].physicalLocation.artifactLocation.uri);
  });

  it('preserves raw issue file paths for SARIF artifact locations', () => {
    const windowsPath = 'C:\\Users\\test\\AppData\\Local\\app\\main.js';
    const issue = {
      id: 'SYNTHETIC_WINDOWS_PATH_CHECK',
      description: 'Synthetic Windows path check',
      file: windowsPath,
      location: { line: 1, column: 0 },
      sample: 'BrowserWindow',
      severity: { name: 'LOW' },
      confidence: { name: 'TENTATIVE' }
    };
    const findings = buildFindings(findingFixture, [issue], null);
    const sarif = buildSarifDocument(null, findings);

    findings[0].file.should.not.equal(windowsPath);
    sarif.runs[0].results[0].locations[0].physicalLocation.artifactLocation.uri.should.equal(windowsPath);
  });

  it('normalizes global/manual-review style findings with N/A file and zero location', () => {
    const issue = {
      id: 'SYNTHETIC_GLOBAL_CHECK',
      description: 'Synthetic global check',
      file: 'N/A',
      location: { line: 0, column: 0 },
      sample: '',
      severity: { name: 'HIGH' },
      confidence: { name: 'CERTAIN' },
      manualReview: true
    };
    const finding = buildFindings(findingFixture, [issue], null)[0];

    finding.file.should.equal('N/A');
    finding.line.should.equal(0);
    finding.column.should.equal(0);
    finding.manual_review.should.equal(true);
    finding.next_agent_hint.should.be.a('string');
  });

  it('preserves issue-level hardening classification in schema v1 and SARIF properties', () => {
    const issues = [
      {
        id: 'SYNTHETIC_HARDENING_CHECK',
        description: 'Synthetic hardening check',
        file: findingFixture,
        location: { line: 1, column: 0 },
        sample: 'new BrowserWindow({ webPreferences: {} })',
        severity: { name: 'INFORMATIONAL' },
        confidence: { name: 'FIRM' },
        properties: {
          issueType: 'finding',
          issueClassification: 'hardening',
          versionContext: {
            electronVersion: '20.0.0',
            electronVersionSource: 'package_json',
            electronVersionConfidence: 'medium',
            defaultBehavior: 'sandbox_default_true'
          }
        }
      },
      {
        id: 'SYNTHETIC_FINDING_CHECK',
        description: 'Synthetic finding check',
        file: findingFixture,
        location: { line: 2, column: 0 },
        sample: 'new BrowserWindow({ webPreferences: { sandbox: false } })',
        severity: { name: 'MEDIUM' },
        confidence: { name: 'FIRM' },
        properties: {
          issueType: 'finding',
          issueClassification: 'finding',
          versionContext: {
            electronVersion: '20.0.0',
            electronVersionSource: 'package_json',
            electronVersionConfidence: 'medium',
            defaultBehavior: 'sandbox_default_true'
          }
        }
      }
    ];
    const findings = buildFindings(findingFixture, issues, createVersionContext({
      electronVersion: '20.0.0',
      electronVersionSource: 'package_json'
    }));
    const sarif = buildSarifDocument(null, findings);

    findings[0].classification.should.equal('hardening');
    findings[0].type.should.equal('finding');
    findings[1].classification.should.equal('finding');
    sarif.runs[0].results[0].properties.type.should.equal('finding');
    sarif.runs[0].results[0].properties.classification.should.equal('hardening');
    sarif.runs[0].results[1].properties.classification.should.equal('finding');
  });

  it('keeps finding, inventory, and auto-derived target IDs distinct for paths that differ only by case', () => {
    const issues = [
      {
        id: 'SYNTHETIC_CHECK',
        description: 'Synthetic check',
        file: '/tmp/Foo.js',
        location: { line: 1, column: 0 },
        sample: 'x',
        severity: { name: 'LOW' },
        confidence: { name: 'CERTAIN' }
      },
      {
        id: 'SYNTHETIC_CHECK',
        description: 'Synthetic check',
        file: '/tmp/foo.js',
        location: { line: 1, column: 0 },
        sample: 'x',
        severity: { name: 'LOW' },
        confidence: { name: 'CERTAIN' }
      }
    ];
    const findings = buildFindings('/tmp', issues, null);
    const inventory = buildInventory('/tmp', {
      '/tmp/Foo.js': { parser_status: 'ok' },
      '/tmp/foo.js': { parser_status: 'ok' }
    });

    const targetRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'electro-case-targets-'));
    const upperPath = path.join(targetRoot, 'Foo.js');
    const lowerPath = path.join(targetRoot, 'foo.js');
    fs.writeFileSync(upperPath, 'console.log("upper");\n');
    fs.writeFileSync(lowerPath, 'console.log("lower");\n');
    const upperRun = buildRunMetadata({ input: upperPath }, null, '2026-01-01T00:00:00.000Z');
    const lowerRun = buildRunMetadata({ input: lowerPath }, null, '2026-01-01T00:00:00.000Z');

    findings[0].result_id.should.not.equal(findings[1].result_id);
    inventory.records[0].entity_id.should.not.equal(inventory.records[1].entity_id);
    upperRun.target_id.should.not.equal(lowerRun.target_id);
  });

  it('selects Electron version provenance from the winning discovered version', async () => {
    const result = await findOldestElectronVersionWithSource({
      pjsonData: { dependencies: { electron: '^41.0.0' } },
      plockData: { dependencies: { electron: { version: '40.0.0' } } }
    });
    const tieResult = await findOldestElectronVersionWithSource({
      pjsonData: { dependencies: { electron: '^40.0.0' } },
      plockData: { dependencies: { electron: { version: '40.0.0' } } }
    });

    result.version.should.equal('40.0.0');
    result.source.should.equal('lockfile');
    tieResult.version.should.equal('40.0.0');
    tieResult.source.should.equal('package_json');
  });

  it('records Electron version provenance in run metadata', () => {
    const cliRun = buildRunMetadata({ input: findingFixture, electronVersionOverride: '41.1.0' }, '41.1.0', '2026-01-01T00:00:00.000Z');
    const packageRun = buildRunMetadata({ input: findingFixture, electronVersionSource: 'package_json' }, '41.1.0', '2026-01-01T00:00:00.000Z');
    const lockRun = buildRunMetadata({ input: findingFixture, electronVersionSource: 'lockfile' }, '41.1.0', '2026-01-01T00:00:00.000Z');

    cliRun.electron_version_source.should.equal('cli');
    cliRun.electron_version_confidence.should.equal('high');
    packageRun.electron_version_source.should.equal('package_json');
    packageRun.electron_version_confidence.should.equal('medium');
    lockRun.electron_version_source.should.equal('lockfile');
    lockRun.electron_version_confidence.should.equal('medium');
  });

  it('records explicit unknown version and fuse state in run metadata', () => {
    const runMetadata = buildRunMetadata({ input: findingFixture }, null, '2026-01-01T00:00:00.000Z');

    should.equal(runMetadata.electron_version, null);
    runMetadata.electron_version_source.should.equal('unknown');
    runMetadata.electron_version_confidence.should.equal('low');
    runMetadata.fuse_state.should.equal('unknown');
    runMetadata.fuse_source.should.equal('unknown');
    runMetadata.fuses.should.deep.equal({});
  });

  it('records plain fuse maps as known explicit fuse context', () => {
    const runMetadata = buildRunMetadata({ input: findingFixture }, null, '2026-01-01T00:00:00.000Z', {
      runAsNode: false,
      cookieEncryption: true
    });
    const finding = buildFindings(findingFixture, [{
      id: 'SYNTHETIC_FUSE_CHECK',
      description: 'Synthetic fuse check',
      file: findingFixture,
      location: { line: 1, column: 0 },
      sample: 'x',
      severity: { name: 'LOW' },
      confidence: { name: 'FIRM' }
    }], null, { runAsNode: false })[0];

    runMetadata.fuse_state.should.equal('known');
    runMetadata.fuse_source.should.equal('explicit');
    runMetadata.fuses.should.deep.equal({ cookieEncryption: true, runAsNode: false });
    finding.version_context.fuse_state.should.equal('known');
    finding.version_context.fuse_source.should.equal('explicit');
  });

  it('threads version provenance and unknown fuse state into finding version_context', () => {
    const versionContext = createVersionContext({
      electronVersion: '20.0.0',
      electronVersionSource: 'package_json'
    });
    const issue = {
      id: 'SYNTHETIC_VERSION_CONTEXT_CHECK',
      description: 'Synthetic version context check',
      file: findingFixture,
      location: { line: 1, column: 0 },
      sample: 'new BrowserWindow({ webPreferences: {} })',
      severity: { name: 'LOW' },
      confidence: { name: 'FIRM' },
      properties: {
        versionContext: {
          defaultBehavior: 'sandbox_default_true'
        }
      }
    };
    const finding = buildFindings(findingFixture, [issue], versionContext)[0];

    finding.version_context.electron_version.should.equal('20.0.0');
    finding.version_context.electron_version_source.should.equal('package_json');
    finding.version_context.electron_version_confidence.should.equal('medium');
    finding.version_context.default_behavior.should.equal('sandbox_default_true');
    finding.version_context.fuse_state.should.equal('unknown');
    finding.version_context.fuse_source.should.equal('unknown');
  });

  it('keeps result IDs stable when only version provenance metadata changes', () => {
    const packageIssue = {
      id: 'SYNTHETIC_VERSION_CONTEXT_CHECK',
      description: 'Synthetic version context check',
      file: findingFixture,
      location: { line: 1, column: 0 },
      sample: 'new BrowserWindow({ webPreferences: {} })',
      severity: { name: 'LOW' },
      confidence: { name: 'FIRM' },
      properties: {
        issueType: 'finding',
        issueClassification: 'hardening',
        versionContext: {
          electronVersion: '20.0.0',
          electronVersionSource: 'package_json',
          electronVersionConfidence: 'medium',
          defaultBehavior: 'sandbox_default_true'
        }
      }
    };
    const lockIssue = {
      id: 'SYNTHETIC_VERSION_CONTEXT_CHECK',
      description: 'Synthetic version context check',
      file: findingFixture,
      location: { line: 1, column: 0 },
      sample: 'new BrowserWindow({ webPreferences: {} })',
      severity: { name: 'LOW' },
      confidence: { name: 'FIRM' },
      properties: {
        issueType: 'finding',
        issueClassification: 'hardening',
        versionContext: {
          electronVersion: '20.0.0',
          electronVersionSource: 'lockfile',
          electronVersionConfidence: 'medium',
          defaultBehavior: 'sandbox_default_true'
        }
      }
    };
    const packageFinding = buildFindings(findingFixture, [packageIssue], createVersionContext({
      electronVersion: '20.0.0',
      electronVersionSource: 'package_json'
    }))[0];
    const lockFinding = buildFindings(findingFixture, [lockIssue], createVersionContext({
      electronVersion: '20.0.0',
      electronVersionSource: 'lockfile'
    }))[0];

    packageFinding.result_id.should.equal(lockFinding.result_id);
  });

  it('writes N/A manual-review findings through the output-directory writer', () => {
    const outputDir = fs.mkdtempSync(path.join(os.tmpdir(), 'electro-structured-na-'));
    const runMetadata = buildRunMetadata({ input: findingFixture, targetId: 'synthetic-target' }, null, '2026-01-01T00:00:00.000Z');
    const issue = {
      id: 'SYNTHETIC_GLOBAL_CHECK',
      description: 'Synthetic global check',
      file: 'N/A',
      location: { line: 0, column: 0 },
      sample: '',
      severity: { name: 'HIGH' },
      confidence: { name: 'CERTAIN' },
      manualReview: true
    };
    const findings = buildFindings(findingFixture, [issue], null);
    const inventory = buildInventory(findingFixture, {});
    const hypotheses = [];
    const parseErrors = [];
    const sarif = buildSarifDocument(null, findings);

    writeOutputDirectory(outputDir, runMetadata, findings, inventory, hypotheses, parseErrors, sarif);

    const sarifDoc = parseJson(path.join(outputDir, 'findings.sarif'));
    const findingsDoc = parseJson(path.join(outputDir, 'findings.json'));

    findingsDoc.findings[0].file.should.equal('N/A');
    findingsDoc.findings[0].manual_review.should.equal(true);
    sarifDoc.runs[0].results[0].locations[0].physicalLocation.artifactLocation.uri.should.equal('file:///');
    sarifDoc.runs[0].results[0].locations[0].physicalLocation.region.startLine.should.equal(1);
  });

  it('writes parser errors into the structured output directory', async function () {
    this.timeout(10000);

    const outputDir = fs.mkdtempSync(path.join(os.tmpdir(), 'electro-structured-errors-'));
    const result = await runFixture(brokenFixture, {
      customScan: nodeIntegrationOnly,
      outputDir
    });

    result.parseErrors.length.should.equal(1);

    const parseErrors = parseJsonl(path.join(outputDir, 'parse_errors.jsonl'));
    const inventoryDoc = parseJson(path.join(outputDir, 'inventory.json'));

    parseErrors.length.should.equal(1);
    parseErrors[0].parser_status.should.equal('error');
    inventoryDoc.records[0].parser_status.should.equal('error');
  });
});
