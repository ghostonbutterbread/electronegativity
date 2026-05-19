import crypto from 'crypto';
import fs from 'fs';
import path from 'path';

import { normalizeFuseContext, normalizeVersionContext } from '../util/electron_context';
import { getRelativePath, is_directory } from '../util';

const VER = require('../../package.json').version;

const SCHEMA_VERSION = '1.0';

function normalizeSlashes(value) {
  return value.replace(/\\/g, '/');
}

function normalizeFileForDisplay(input, file) {
  if (!file || file === 'N/A')
    return 'N/A';

  if (!path.isAbsolute(file)) {
    const normalizedFile = normalizeSlashes(file);
    const normalizedInput = input ? normalizeSlashes(input) : null;
    if (normalizedInput && normalizedFile.startsWith(`${normalizedInput}/`))
      return normalizeSlashes(path.relative(input, file));

    return normalizedFile;
  }

  return normalizeSlashes(getRelativePath(input, file));
}

function normalizeFileForId(input, file) {
  return normalizeFileForDisplay(input, file);
}

const INVENTORY_KEY_FILE_PARTS = {
  source_file: [1],
  renderer_container: [1],
  web_preferences: [2],
  preload_script: [2],
  load_target: [2],
  session: [1, 2],
  navigation_handler: [2],
  webview_attach_handler: [2],
  global_sandbox: [1]
};

function normalizeInventoryKey(input, key) {
  if (!key || typeof key !== 'string')
    return key;

  const parts = key.split('|');
  if (parts.length < 2)
    return key;

  (INVENTORY_KEY_FILE_PARTS[parts[0]] || []).forEach(index => {
    if (parts[index])
      parts[index] = normalizeFileForId(input, parts[index]);
  });

  return parts.join('|');
}

function normalizeComponentRecord(input, record) {
  const normalizedKey = normalizeInventoryKey(input, record.key);
  const entityId = stableHash(normalizedKey);

  return Object.assign({}, record, {
    key: normalizedKey,
    type: 'inventory',
    classification: 'inventory',
    inventory_id: entityId,
    entity_id: entityId,
    file: normalizeFileForDisplay(input, record.file)
  });
}

function normalizeComponentRelationship(input, relationship) {
  const normalizedRelationship = Object.assign({}, relationship, {
    from_key: normalizeInventoryKey(input, relationship.from_key),
    to_key: normalizeInventoryKey(input, relationship.to_key),
    file: relationship.file ? normalizeFileForDisplay(input, relationship.file) : null,
    line: relationship.line != null ? relationship.line : null,
    column: relationship.column != null ? relationship.column : null
  });

  if (normalizedRelationship.relationship_type === 'global_sandbox_state')
    normalizedRelationship.relationship_type = 'has_global_sandbox_evidence';

  return normalizedRelationship;
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

function issueType(issue) {
  return issue && issue.properties && issue.properties.issueType ? issue.properties.issueType : 'finding';
}

function issueClassification(issue) {
  return issue && issue.properties && issue.properties.issueClassification ? issue.properties.issueClassification : 'finding';
}

function fingerprintProperties(issue) {
  const properties = issue && issue.properties ? Object.assign({}, issue.properties) : null;

  if (!properties)
    return null;

  delete properties.issueType;
  delete properties.issueClassification;

  if (properties.versionContext && typeof properties.versionContext === 'object' && !Array.isArray(properties.versionContext)) {
    const versionContext = Object.assign({}, properties.versionContext);
    delete versionContext.electronVersionSource;
    delete versionContext.electronVersionConfidence;

    if (Object.keys(versionContext).length > 0)
      properties.versionContext = versionContext;
    else
      delete properties.versionContext;
  }

  return properties;
}

function findingEvidence(issue) {
  return {
    sample: issue && issue.sample ? issue.sample : null,
    properties: fingerprintProperties(issue)
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

function findingVersionContext(issue, versionContext, fuseContext) {
  const issueVersionContext = issue && issue.properties && issue.properties.versionContext ? issue.properties.versionContext : {};

  return {
    electron_version: versionContext.electronVersion || null,
    electron_version_source: versionContext.source,
    electron_version_confidence: versionContext.confidence,
    default_behavior: issueVersionContext.defaultBehavior || null,
    fuse_state: fuseContext.state,
    fuse_source: fuseContext.source
  };
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

function sortRelationships(relationships) {
  return relationships.sort((a, b) => {
    const typeCompare = a.relationship_type.localeCompare(b.relationship_type);
    if (typeCompare !== 0)
      return typeCompare;

    const fromCompare = a.from_entity_id.localeCompare(b.from_entity_id);
    if (fromCompare !== 0)
      return fromCompare;

    const toCompare = a.to_entity_id.localeCompare(b.to_entity_id);
    if (toCompare !== 0)
      return toCompare;

    return a.relationship_id.localeCompare(b.relationship_id);
  });
}

export function buildRunMetadata(options, electronVersion, generatedAt, fuseContextValue = null) {
  const versionContext = normalizeVersionContext(electronVersion, options);
  const fuseContext = normalizeFuseContext(fuseContextValue);

  return {
    schema_version: SCHEMA_VERSION,
    scanner_version: VER,
    target_id: targetId(options),
    input_kind: inputKind(options.input),
    electron_version: versionContext.electronVersion || null,
    electron_version_source: versionContext.source,
    electron_version_confidence: versionContext.confidence,
    fuse_state: fuseContext.state,
    fuse_source: fuseContext.source,
    fuses: fuseContext.fuses,
    generated_at: generatedAt
  };
}

export function buildFindings(input, issues, electronVersion, fuseContextValue = null) {
  const versionContext = normalizeVersionContext(electronVersion);
  const fuseContext = normalizeFuseContext(fuseContextValue);
  const findings = issues.map(issue => {
    const file = normalizeFileForDisplay(input, issue.file);
    const sarifFile = issue.file && issue.file !== 'N/A' ? issue.file : 'N/A';
    const resultId = findingId(input, issue);

    return {
      type: issueType(issue),
      classification: issueClassification(issue),
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
      version_context: findingVersionContext(issue, versionContext, fuseContext),
      validation_state: 'static_only',
      manual_review: Boolean(issue.manualReview),
      file_classification: issueFileClassification(issue),
      next_agent_hint: issue.manualReview ? 'Review the surrounding Electron trust boundary before triage.' : null
    };
  });

  return sortFindings(findings);
}

export function buildInventory(input, fileClassifications, componentInventory = null) {
  const files = Object.keys(fileClassifications || {});
  const sourceFileRecords = files.map(file => {
    const normalizedFile = normalizeFileForDisplay(input, file);
    const classification = fileClassifications[file] || {};
    const entityKey = `source_file|${normalizeFileForId(input, file)}`;
    const entityId = stableHash(entityKey);

    return {
      entity_key: entityKey,
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

  const recordsByKey = new Map();
  sourceFileRecords.forEach(record => {
    recordsByKey.set(record.entity_key, record);
  });

  for (const record of (componentInventory && componentInventory.records) || []) {
    if (!record || !record.key)
      continue;

    const normalizedRecord = normalizeComponentRecord(input, record);
    if (recordsByKey.has(normalizedRecord.key))
      continue;

    const normalizedRecordKey = normalizedRecord.key;
    delete normalizedRecord.key;
    recordsByKey.set(normalizedRecordKey, normalizedRecord);
  }

  const entityIdsByKey = new Map();
  Array.from(recordsByKey.entries()).forEach(([key, record]) => {
    entityIdsByKey.set(key, record.entity_id);
  });

  const relationshipsByKey = new Map();
  for (const relationship of (componentInventory && componentInventory.relationships) || []) {
    if (!relationship || !relationship.from_key || !relationship.to_key)
      continue;

    const normalizedInputRelationship = normalizeComponentRelationship(input, relationship);
    if (!entityIdsByKey.has(normalizedInputRelationship.from_key) || !entityIdsByKey.has(normalizedInputRelationship.to_key))
      continue;

    const relationshipFingerprint = {
      relationship_type: normalizedInputRelationship.relationship_type,
      from_key: normalizedInputRelationship.from_key,
      to_key: normalizedInputRelationship.to_key,
      file: normalizedInputRelationship.file,
      line: normalizedInputRelationship.line,
      column: normalizedInputRelationship.column
    };
    const relationshipId = stableHash(stableStringify(relationshipFingerprint));
    if (relationshipsByKey.has(relationshipId))
      continue;

    const normalizedRelationship = Object.assign({}, normalizedInputRelationship, {
      relationship_id: relationshipId,
      from_entity_id: entityIdsByKey.get(normalizedInputRelationship.from_key),
      to_entity_id: entityIdsByKey.get(normalizedInputRelationship.to_key)
    });
    delete normalizedRelationship.key;
    delete normalizedRelationship.from_key;
    delete normalizedRelationship.to_key;
    relationshipsByKey.set(relationshipId, normalizedRelationship);
  }

  const records = Array.from(recordsByKey.values()).map(record => {
    if (!record.entity_key)
      return record;

    const normalizedRecord = Object.assign({}, record);
    delete normalizedRecord.entity_key;
    return normalizedRecord;
  });

  return {
    schema_version: SCHEMA_VERSION,
    records: sortInventory(records),
    relationships: sortRelationships(Array.from(relationshipsByKey.values()))
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
        type: finding.type,
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
    `- Fuse state: ${runMetadata.fuse_state}`,
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
      fuse_state: runMetadata.fuse_state,
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
