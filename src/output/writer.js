import fs from 'fs';
import path from 'path';

import {
  buildElectronTeamContextPacket,
  buildFindingsDocument,
  buildSummaryMarkdown
} from './schema';

const CONTEXT_PACKET_FILENAME = 'electron-team-context.json';

function writeJson(filename, value) {
  fs.writeFileSync(filename, `${JSON.stringify(value, null, 2)}\n`);
}

function writeJsonl(filename, records) {
  const body = records.map(record => JSON.stringify(record)).join('\n');
  fs.writeFileSync(filename, body ? `${body}\n` : '');
}

export function writeOutputDirectory(outputDir, runMetadata, findings, inventory, hypotheses, parseErrors, sarif) {
  fs.mkdirSync(outputDir, { recursive: true });

  writeJson(path.join(outputDir, 'run.json'), runMetadata);
  writeJson(path.join(outputDir, 'findings.json'), buildFindingsDocument(findings, runMetadata.generated_at));
  writeJson(path.join(outputDir, 'findings.sarif'), sarif);
  writeJson(path.join(outputDir, 'inventory.json'), inventory);
  writeJsonl(path.join(outputDir, 'hypotheses.jsonl'), hypotheses);
  writeJsonl(path.join(outputDir, 'parse_errors.jsonl'), parseErrors);
  fs.writeFileSync(path.join(outputDir, 'summary.md'), `${buildSummaryMarkdown(runMetadata, findings, inventory, hypotheses, parseErrors)}\n`);
  writeJson(path.join(outputDir, CONTEXT_PACKET_FILENAME), buildElectronTeamContextPacket(runMetadata, findings, inventory, hypotheses, parseErrors));
}

export function contextPacketFilename() {
  return CONTEXT_PACKET_FILENAME;
}
