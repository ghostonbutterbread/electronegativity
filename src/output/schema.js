import crypto from 'crypto';
import fs from 'fs';
import path from 'path';

import { getRelativePath, is_directory } from '../util';

const VER = require('../../package.json').version;

const SCHEMA_VERSION = '1.0';

function normalizeSlashes(value) {
  return value.replace(/\\/g, '/');
}

function normalizeFileForDisplay(input, file) {
  if (!file || file === 'N/A')
    return 'N/A';

  if (!path.isAbsolute(file))
    return normalizeSlashes(file);

  return normalizeSlashes(getRelativePath(input, file));
}

function normalizeFileForId(input, file) {
  return normalizeFileForDisplay(input, file);
}

function sortObject(value) {
  if (Array.isArray(value))
    return value.map(sortObject);

  if (value && typeof value === 'object') {
    return Object.keys(value).sort().reduce((result, key) => {
      result[key] = sortObject(value[key]);
      return result;
    }, {});
  }

  return value;
}

function stableStringify(value) {
  return JSON.stringify(sortObject(value));
}

function stableHash(value) {
  return crypto.createHash('sha256').update(String(value)).digest('hex');
}

function issueFileClassification(issue) {
  const classification = issue && issue.fileClassification ? issue.fileClassification : {};

  return {
    is_minified: Boolean(classification.is_minified),
    is_bundle: Boolean(classification.is_bundle),
    vendor_or_generated: Boolean(classification.vendor_or_generated),
    source_map_available: Boolean(classification.source_map_available),
    parser_status: classification.parser_status || 'unknown'
  };
}

function severityName(issue) {
  const severity = issue && issue.severity && issue.severity.name ? issue.severity.name : 'INFORMATIONAL';

  switch (severity) {
    case 'HIGH':
      return 'high';
    case 'MEDIUM':
      return 'medium';
    case 'LOW':
      return 'low';
    default:
      return 'info';
  }
}

function confidenceName(issue) {
  const confidence = issue && issue.confidence && issue.confidence.name ? issue.confidence.name : 'TENTATIVE';

  switch (confidence) {
    case 'CERTAIN':
      return 'high';
    case 'FIRM':
      return 'medium';
    default:
      return 'low';
  }
}

function confidenceReasons(issue) {
  const reasons = [];
  const classification = issueFileClassification(issue);

  if (issue && issue.confidence && issue.confidence.name)
    reasons.push(`legacy confidence: ${issue.confidence.name.toLowerCase()}`);
  if (issue && issue.manualReview)
    reasons.push('manual review required');
  if (classification.is_minified)
    reasons.push('file classified as minified');
  if (classification.is_bundle)
    reasons.push('file classified as bundled');
  if (classification.vendor_or_generated)
    reasons.push('file classified as vendor_or_generated');

  return reasons;
}

function findingEvidence(issue) {
  return {
    sample: issue && issue.sample ? issue.sample : null,
    properties: issue && issue.properties ? issue.properties : null
  };
}

function findingId(input, issue) {
  const location = issue && issue.location ? issue.location : {};
  const evidenceHash = stableHash(stableStringify(findingEvidence(issue)));
  const parts = [
    issue && issue.id ? issue.id : 'UNKNOWN_CHECK',
    normalizeFileForId(input, issue && issue.file),
    location.line || 0,
    location.column || 0,
    evidenceHash
  ];

  return stableHash(parts.join('|'));
}

function inputKind(input) {
  if (path.extname(input).toLowerCase() === '.asar')
    return 'asar';

  if (!is_directory(input))
    return 'file';

  return fs.existsSync(path.join(input, 'package.json')) ? 'package_root' : 'directory';
}

function targetId(options) {
  if (options.targetId)
    return options.targetId;

  return stableHash(normalizeSlashes(path.resolve(options.input)));
}

function versionSource(options, electronVersion) {
  if (options.electronVersionOverride)
    return 'cli';

  return electronVersion ? (options.electronVersionSource || 'unknown') : 'unknown';
}

function versionConfidence(options, electronVersion) {
  if (options.electronVersionOverride)
    return 'high';
  if (options.electronVersionSource === 'package_json' || options.electronVersionSource === 'lockfile')
    return 'medium';

  return electronVersion ? 'low' : 'low';
}

function sortFindings(findings) {
  return findings.sort((a, b) => {
    const fileCompare = a.file.localeCompare(b.file);
    if (fileCompare !== 0)
      return fileCompare;

    const lineCompare = (a.line || 0) - (b.line || 0);
    if (lineCompare !== 0)
      return lineCompare;

    const columnCompare = (a.column || 0) - (b.column || 0);
    if (columnCompare !== 0)
      return columnCompare;

    const checkCompare = a.check_id.localeCompare(b.check_id);
    if (checkCompare !== 0)
      return checkCompare;

    return a.result_id.localeCompare(b.result_id);
  });
}

function sortInventory(records) {
  return records.sort((a, b) => {
    const fileCompare = a.file.localeCompare(b.file);
    if (fileCompare !== 0)
      return fileCompare;

    return a.entity_id.localeCompare(b.entity_id);
  });
}

export function buildRunMetadata(options, electronVersion, generatedAt) {
  return {
    schema_version: SCHEMA_VERSION,
    scanner_version: VER,
    target_id: targetId(options),
    input_kind: inputKind(options.input),
    electron_version: electronVersion || null,
    electron_version_source: versionSource(options, electronVersion),
    electron_version_confidence: versionConfidence(options, electronVersion),
    generated_at: generatedAt
  };
}

export function buildFindings(input, issues, electronVersion) {
  const findings = issues.map(issue => {
    const file = normalizeFileForDisplay(input, issue.file);
    const sarifFile = issue.file && issue.file !== 'N/A' ? issue.file : 'N/A';
    const resultId = findingId(input, issue);

    return {
      type: 'finding',
      classification: 'finding',
      check_id: issue.id,
      result_id: resultId,
      title: issue.description,
      severity: severityName(issue),
      confidence: confidenceName(issue),
      confidence_reasons: confidenceReasons(issue),
      file,
      sarif_file: sarifFile,
      line: issue.location ? issue.location.line : null,
      column: issue.location ? issue.location.column : null,
      evidence: issue.sample || null,
      electron_component: null,
      affected_window_or_channel: null,
      trust_boundary: null,
      version_context: {
        electron_version: electronVersion || null,
        default_behavior: null
      },
      validation_state: 'static_only',
      manual_review: Boolean(issue.manualReview),
      file_classification: issueFileClassification(issue),
      next_agent_hint: issue.manualReview ? 'Review the surrounding Electron trust boundary before triage.' : null
    };
  });

  return sortFindings(findings);
}

export function buildInventory(input, fileClassifications) {
  const files = Object.keys(fileClassifications || {});
  const records = files.map(file => {
    const normalizedFile = normalizeFileForDisplay(input, file);
    const classification = fileClassifications[file] || {};
    const entityId = stableHash(`source_file|${normalizeFileForId(input, file)}`);

    return {
      type: 'inventory',
      classification: 'inventory',
      inventory_id: entityId,
      entity_id: entityId,
      entity_type: 'source_file',
      title: 'Scanned source file',
      file: normalizedFile,
      parser_status: classification.parser_status || 'unknown',
      file_classification: {
        is_minified: Boolean(classification.is_minified),
        is_bundle: Boolean(classification.is_bundle),
        vendor_or_generated: Boolean(classification.vendor_or_generated),
        source_map_present: Boolean(classification.source_map_present),
        source_map_available: Boolean(classification.source_map_available),
        parser_status: classification.parser_status || 'unknown'
      }
    };
  });

  return {
    schema_version: SCHEMA_VERSION,
    records: sortInventory(records),
    relationships: []
  };
}

export function buildHypotheses() {
  return [];
}

export function buildFindingsDocument(findings, generatedAt) {
  return {
    schema_version: SCHEMA_VERSION,
    generated_at: generatedAt,
    findings
  };
}

export function buildHypothesesDocument(hypotheses) {
  return {
    schema_version: SCHEMA_VERSION,
    count: hypotheses.length
  };
}

export function buildSarifDocument(root, findings) {
  const rulesSeen = new Set();
  const rules = [];
  const results = findings.map(finding => {
    if (!rulesSeen.has(finding.check_id)) {
      rulesSeen.add(finding.check_id);
      rules.push({
        id: finding.check_id,
        fullDescription: {
          text: finding.title
        },
        properties: {
          category: 'Security'
        },
        helpUri: `https://github.com/doyensec/electronegativity/wiki/${finding.check_id}`,
        help: {
          text: `https://github.com/doyensec/electronegativity/wiki/${finding.check_id}`
        }
      });
    }

    return {
      ruleId: finding.check_id,
      ruleIndex: rules.findIndex(rule => rule.id === finding.check_id),
      level: finding.manual_review ? 'note' : 'warning',
      message: {
        text: finding.title
      },
      partialFingerprints: {
        resultId: finding.result_id
      },
      properties: {
        result_id: finding.result_id,
        classification: finding.classification,
        confidence: finding.confidence,
        confidence_reasons: finding.confidence_reasons,
        validation_state: finding.validation_state,
        file_classification: finding.file_classification
      },
      locations: [
        {
          physicalLocation: {
            artifactLocation: {
              uri: finding.sarif_file !== 'N/A' ? finding.sarif_file : 'file:///'
            },
            region: {
              startLine: finding.line === 0 ? 1 : (finding.line || 1),
              startColumn: finding.column != null ? finding.column + 1 : 1,
              charLength: finding.evidence ? finding.evidence.length : 0
            }
          }
        }
      ]
    };
  });

  const run = {
    tool: {
      driver: {
        version: `${VER}`,
        informationUri: 'https://github.com/doyensec/electronegativity',
        name: 'Electronegativity',
        fullName: 'Electronegativity is a tool to identify misconfigurations and security anti-patterns in Electron applications',
        rules
      }
    },
    results
  };

  if (root) {
    run.invocations = [
      {
        workingDirectory: {
          uri: `file:///${root}`
        },
        executionSuccessful: true
      }
    ];
  }

  return {
    $schema: 'http://json.schemastore.org/sarif-2.1.0',
    version: '2.1.0',
    runs: [run]
  };
}

export function buildSummaryMarkdown(runMetadata, findings, inventory, hypotheses, parseErrors) {
  return [
    '# Electronegativity Audit Summary',
    '',
    `- Schema version: ${runMetadata.schema_version}`,
    `- Scanner version: ${runMetadata.scanner_version}`,
    `- Target ID: ${runMetadata.target_id}`,
    `- Input kind: ${runMetadata.input_kind}`,
    `- Electron version: ${runMetadata.electron_version || 'unknown'}`,
    `- Findings: ${findings.length}`,
    `- Inventory records: ${inventory.records.length}`,
    `- Hypotheses: ${hypotheses.length}`,
    `- Parse errors: ${parseErrors.length}`
  ].join('\n');
}

export function buildElectronTeamContextPacket(runMetadata, findings, inventory, hypotheses, parseErrors) {
  return {
    schema_version: SCHEMA_VERSION,
    packet_type: 'electron_team_context',
    generated_at: runMetadata.generated_at,
    target: {
      target_id: runMetadata.target_id,
      input_kind: runMetadata.input_kind,
      electron_version: runMetadata.electron_version,
      validation_state: 'static_only'
    },
    artifact_files: {
      run: 'run.json',
      findings: 'findings.json',
      sarif: 'findings.sarif',
      inventory: 'inventory.json',
      hypotheses: 'hypotheses.jsonl',
      parse_errors: 'parse_errors.jsonl',
      summary: 'summary.md'
    },
    counts: {
      findings: findings.length,
      inventory_records: inventory.records.length,
      hypotheses: hypotheses.length,
      parse_errors: parseErrors.length
    },
    triage: {
      manual_review_findings: findings.filter(finding => finding.manual_review).map(finding => finding.result_id),
      next_step: 'Use findings and inventory as the baseline map before deeper Electron Team tracing.'
    }
  };
}
