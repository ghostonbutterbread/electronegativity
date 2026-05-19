import fs from 'fs';
import os from 'os';
import path from 'path';

import run from '../src/runner';
import { Parser } from '../src/parser';
import { buildFindings, buildInventory } from '../src/output';
import { PreloadIpcCollector } from '../src/inventory';

let chai = require('chai');
let should = chai.should();

function writeFixtureFiles(files) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'electro-phase6-'));

  Object.keys(files).forEach(relativePath => {
    const absolutePath = path.join(root, relativePath);
    fs.mkdirSync(path.dirname(absolutePath), { recursive: true });
    fs.writeFileSync(absolutePath, files[relativePath]);
  });

  return root;
}

function removeFixtureRoot(root) {
  if (fs.rmSync)
    fs.rmSync(root, { recursive: true, force: true });
  else
    fs.rmdirSync(root, { recursive: true });
}

function parseJson(file) {
  return JSON.parse(fs.readFileSync(file, 'utf8'));
}

function collectPhase6(files) {
  const root = writeFixtureFiles(files);
  const parser = new Parser(false, true);
  const collector = new PreloadIpcCollector();
  const fileClassifications = {};

  try {
    Object.keys(files).forEach(relativePath => {
      const absolutePath = path.join(root, relativePath);
      const [type, data, content] = parser.parse(absolutePath, fs.readFileSync(absolutePath));
      fileClassifications[absolutePath] = parser.getFileClassification(absolutePath);
      collector.collect(absolutePath, type, data, content, fileClassifications[absolutePath]);
    });

    const audit = collector.buildAuditResults();

    return {
      root,
      issues: audit.issues,
      findings: buildFindings(root, audit.issues, null),
      inventory: buildInventory(root, fileClassifications, audit.componentInventory)
    };
  } catch (error) {
    removeFixtureRoot(root);
    throw error;
  }
}

describe('Phase 6 preload and IPC audit', () => {
  it('distinguishes allowlisted preload wrappers from raw IPC, arbitrary forwarding, and privileged API exposure', () => {
    const fixture = collectPhase6({
      'preload.js': `
        const { contextBridge, ipcRenderer, shell } = require('electron');
        const SAFE_CHANNELS = ['metrics', 'ping'];

        contextBridge.exposeInMainWorld('safeApi', {
          send(channel, payload) {
            if (!SAFE_CHANNELS.includes(channel)) throw new Error('blocked');
            return ipcRenderer.send(channel, payload);
          }
        });

        contextBridge.exposeInMainWorld('unsafeApi', {
          ipc: ipcRenderer,
          proc: process,
          send(channel, payload) {
            return ipcRenderer.invoke(channel, payload);
          },
          open(url) {
            return shell.openExternal(url);
          }
        });
      `
    });

    try {
      fixture.issues.filter(issue => issue.id === 'PRELOAD_RAW_IPC_EXPOSURE').length.should.equal(1);
      fixture.issues.filter(issue => issue.id === 'PRELOAD_ARBITRARY_CHANNEL_FORWARD').length.should.equal(1);
      fixture.issues.filter(issue => issue.id === 'PRELOAD_NODE_PRIMITIVE_EXPOSURE').length.should.equal(1);
      fixture.issues.filter(issue => issue.id === 'PRELOAD_DANGEROUS_API_WRAPPER').length.should.equal(1);

      const bridgeRecords = fixture.inventory.records.filter(record => record.entity_type === 'preload_bridge');
      bridgeRecords.map(record => record.global_name).sort().should.deep.equal(['safeApi', 'unsafeApi']);

      const safeBridge = bridgeRecords.find(record => record.global_name === 'safeApi');
      const unsafeBridge = bridgeRecords.find(record => record.global_name === 'unsafeApi');

      should.exist(safeBridge);
      should.exist(unsafeBridge);
      safeBridge.arbitrary_channel_methods.should.deep.equal([]);
      unsafeBridge.raw_ipc_exposed.should.equal(true);
      unsafeBridge.node_primitives_exposed.should.deep.equal(['process']);
      unsafeBridge.arbitrary_channel_methods.should.deep.equal(['send']);
      unsafeBridge.dangerous_wrappers.should.deep.equal(['open: shell.openExternal']);
    } finally {
      removeFixtureRoot(fixture.root);
    }
  });

  it('flags unvalidated dangerous IPC handlers while preserving validated channel inventory', () => {
    const fixture = collectPhase6({
      'main.js': `
        const { ipcMain } = require('electron');
        const fs = require('fs');
        const allowedOrigins = ['https://app.example.com'];

        ipcMain.handle('validated-export', async (event, targetPath) => {
          const origin = new URL(event.senderFrame.url).origin;
          if (!allowedOrigins.includes(origin)) throw new Error('blocked');
          return fs.readFileSync(targetPath, 'utf8');
        });

        ipcMain.on('export-file', (event, targetPath) => {
          fs.writeFileSync(targetPath, 'data');
        });

        ipcMain.handle('ping', (event, payload) => payload);
      `
    });

    try {
      const missingValidationChannels = fixture.issues
        .filter(issue => issue.id === 'IPC_SENDER_VALIDATION_MISSING')
        .map(issue => issue.properties.affectedChannel)
        .sort();
      const dangerousUnvalidatedChannels = fixture.issues
        .filter(issue => issue.id === 'IPC_DANGEROUS_SINK_NO_SENDER_VALIDATION')
        .map(issue => issue.properties.affectedChannel)
        .sort();

      missingValidationChannels.should.deep.equal(['export-file', 'ping']);
      dangerousUnvalidatedChannels.should.deep.equal(['export-file']);

      const channelRecords = fixture.inventory.records.filter(record => record.entity_type === 'ipc_channel');
      const validatedChannel = channelRecords.find(record => record.channel === 'validated-export');
      const exportChannel = channelRecords.find(record => record.channel === 'export-file');

      should.exist(validatedChannel);
      should.exist(exportChannel);
      validatedChannel.visible_sender_validation.should.equal(true);
      validatedChannel.dangerous_sinks.should.deep.equal(['fs.readFileSync']);
      exportChannel.visible_sender_validation.should.equal(false);
      exportChannel.dangerous_sinks.should.deep.equal(['fs.writeFileSync']);
    } finally {
      removeFixtureRoot(fixture.root);
    }
  });

  it('flags dangerous IPC sinks that run before sender validation', () => {
    const fixture = collectPhase6({
      'main.js': `
        const { ipcMain } = require('electron');
        const fs = require('fs');
        const allowedOrigins = ['https://app.example.com'];

        ipcMain.handle('late-validation-export', (event, targetPath) => {
          const origin = new URL(event.senderFrame.url).origin;
          const data = fs.readFileSync(targetPath, 'utf8');
          if (!allowedOrigins.includes(origin)) throw new Error('blocked');
          return data;
        });
      `
    });

    try {
      const dangerousUnvalidatedChannels = fixture.issues
        .filter(issue => issue.id === 'IPC_DANGEROUS_SINK_NO_SENDER_VALIDATION')
        .map(issue => issue.properties.affectedChannel);
      const missingValidationChannels = fixture.issues
        .filter(issue => issue.id === 'IPC_SENDER_VALIDATION_MISSING')
        .map(issue => issue.properties.affectedChannel);
      const channelRecord = fixture.inventory.records.find(record => record.entity_type === 'ipc_channel');

      dangerousUnvalidatedChannels.should.deep.equal(['late-validation-export']);
      missingValidationChannels.should.deep.equal(['late-validation-export']);
      should.exist(channelRecord);
      channelRecord.visible_sender_validation.should.equal(false);
    } finally {
      removeFixtureRoot(fixture.root);
    }
  });

  it('flags dangerous IPC sinks before nested positive-form sender validation', () => {
    const fixture = collectPhase6({
      'main.js': `
        const { ipcMain } = require('electron');
        const fs = require('fs');
        const allowedOrigins = ['https://app.example.com'];

        ipcMain.handle('nested-late', (event, targetPath) => {
          const origin = new URL(event.senderFrame.url).origin;
          fs.readFileSync(targetPath, 'utf8');
          if (targetPath) {
            if (allowedOrigins.includes(origin)) {
              return 'ok';
            } else {
              throw new Error('blocked');
            }
          }
        });
      `
    });

    try {
      const missingValidationChannels = fixture.issues
        .filter(issue => issue.id === 'IPC_SENDER_VALIDATION_MISSING')
        .map(issue => issue.properties.affectedChannel);
      const dangerousUnvalidatedChannels = fixture.issues
        .filter(issue => issue.id === 'IPC_DANGEROUS_SINK_NO_SENDER_VALIDATION')
        .map(issue => issue.properties.affectedChannel);
      const channelRecord = fixture.inventory.records.find(record => record.entity_type === 'ipc_channel');

      missingValidationChannels.should.deep.equal(['nested-late']);
      dangerousUnvalidatedChannels.should.deep.equal(['nested-late']);
      should.exist(channelRecord);
      channelRecord.visible_sender_validation.should.equal(false);
    } finally {
      removeFixtureRoot(fixture.root);
    }
  });

  it('flags dangerous IPC sinks before positive-form sender validation with later protected return', () => {
    const fixture = collectPhase6({
      'main.js': `
        const { ipcMain } = require('electron');
        const fs = require('fs');
        const allowedOrigins = ['https://app.example.com'];

        ipcMain.handle('late-positive-validation-return', (event, targetPath) => {
          const origin = new URL(event.senderFrame.url).origin;
          const data = fs.readFileSync(targetPath, 'utf8');
          if (allowedOrigins.includes(origin)) {
            console.log('allowed');
          } else {
            throw new Error('blocked');
          }
          return data;
        });
      `
    });

    try {
      const missingValidationChannels = fixture.issues
        .filter(issue => issue.id === 'IPC_SENDER_VALIDATION_MISSING')
        .map(issue => issue.properties.affectedChannel);
      const dangerousUnvalidatedChannels = fixture.issues
        .filter(issue => issue.id === 'IPC_DANGEROUS_SINK_NO_SENDER_VALIDATION')
        .map(issue => issue.properties.affectedChannel);
      const channelRecord = fixture.inventory.records.find(record => record.entity_type === 'ipc_channel');

      missingValidationChannels.should.deep.equal(['late-positive-validation-return']);
      dangerousUnvalidatedChannels.should.deep.equal(['late-positive-validation-return']);
      should.exist(channelRecord);
      channelRecord.visible_sender_validation.should.equal(false);
    } finally {
      removeFixtureRoot(fixture.root);
    }
  });

  it('flags dangerous IPC sinks that run before positive-form sender validation with else throw', () => {
    const fixture = collectPhase6({
      'main.js': `
        const { ipcMain } = require('electron');
        const fs = require('fs');
        const allowedOrigins = ['https://app.example.com'];

        ipcMain.handle('late-positive-validation-export', (event, targetPath) => {
          const origin = new URL(event.senderFrame.url).origin;
          const data = fs.readFileSync(targetPath, 'utf8');
          if (allowedOrigins.includes(origin)) {
            return data;
          } else {
            throw new Error('blocked');
          }
        });
      `
    });

    try {
      const missingValidationChannels = fixture.issues
        .filter(issue => issue.id === 'IPC_SENDER_VALIDATION_MISSING')
        .map(issue => issue.properties.affectedChannel);
      const dangerousUnvalidatedChannels = fixture.issues
        .filter(issue => issue.id === 'IPC_DANGEROUS_SINK_NO_SENDER_VALIDATION')
        .map(issue => issue.properties.affectedChannel);
      const channelRecord = fixture.inventory.records.find(record => record.entity_type === 'ipc_channel');

      missingValidationChannels.should.deep.equal(['late-positive-validation-export']);
      dangerousUnvalidatedChannels.should.deep.equal(['late-positive-validation-export']);
      should.exist(channelRecord);
      channelRecord.visible_sender_validation.should.equal(false);
    } finally {
      removeFixtureRoot(fixture.root);
    }
  });

  it('flags positive-form sender validation when earlier protected work uses a block-local dangerous alias', () => {
    const fixture = collectPhase6({
      'main.js': `
        const { ipcMain } = require('electron');
        const allowedOrigins = ['https://app.example.com'];

        ipcMain.handle('block-local-alias-before-positive-validation', (event, targetPath) => {
          const origin = new URL(event.senderFrame.url).origin;
          if (targetPath) {
            const fs = require('fs');
            fs.readFileSync(targetPath, 'utf8');
          }
          if (allowedOrigins.includes(origin)) {
            return 'ok';
          } else {
            throw new Error('blocked');
          }
        });
      `
    });

    try {
      const missingValidationChannels = fixture.issues
        .filter(issue => issue.id === 'IPC_SENDER_VALIDATION_MISSING')
        .map(issue => issue.properties.affectedChannel);
      const dangerousUnvalidatedChannels = fixture.issues
        .filter(issue => issue.id === 'IPC_DANGEROUS_SINK_NO_SENDER_VALIDATION')
        .map(issue => issue.properties.affectedChannel);
      const channelRecord = fixture.inventory.records.find(record => record.entity_type === 'ipc_channel');

      missingValidationChannels.should.deep.equal(['block-local-alias-before-positive-validation']);
      dangerousUnvalidatedChannels.should.deep.equal(['block-local-alias-before-positive-validation']);
      should.exist(channelRecord);
      channelRecord.visible_sender_validation.should.equal(false);
      channelRecord.dangerous_sinks.should.deep.equal(['fs.readFileSync']);
    } finally {
      removeFixtureRoot(fixture.root);
    }
  });

  it('detects function-local ipcMain require registrations', () => {
    const fixture = collectPhase6({
      'main.js': `
        function install() {
          const { ipcMain } = require('electron');
          const fs = require('fs');

          ipcMain.handle('local-register', (event, targetPath) => {
            return fs.readFileSync(targetPath, 'utf8');
          });
        }
      `
    });

    try {
      const missingValidationChannels = fixture.issues
        .filter(issue => issue.id === 'IPC_SENDER_VALIDATION_MISSING')
        .map(issue => issue.properties.affectedChannel);
      const dangerousUnvalidatedChannels = fixture.issues
        .filter(issue => issue.id === 'IPC_DANGEROUS_SINK_NO_SENDER_VALIDATION')
        .map(issue => issue.properties.affectedChannel);
      const channelRecord = fixture.inventory.records.find(record => record.entity_type === 'ipc_channel');

      missingValidationChannels.should.deep.equal(['local-register']);
      dangerousUnvalidatedChannels.should.deep.equal(['local-register']);
      should.exist(channelRecord);
      channelRecord.channel.should.equal('local-register');
      channelRecord.dangerous_sinks.should.deep.equal(['fs.readFileSync']);
    } finally {
      removeFixtureRoot(fixture.root);
    }
  });

  it('detects handler-local destructured fs require dangerous sinks', () => {
    const fixture = collectPhase6({
      'main.js': `
        const { ipcMain } = require('electron');

        ipcMain.handle('local-destructured-read', (event, targetPath) => {
          const { readFileSync } = require('fs');
          return readFileSync(targetPath, 'utf8');
        });
      `
    });

    try {
      const dangerousUnvalidatedChannels = fixture.issues
        .filter(issue => issue.id === 'IPC_DANGEROUS_SINK_NO_SENDER_VALIDATION')
        .map(issue => issue.properties.affectedChannel);
      const channelRecord = fixture.inventory.records.find(record => record.entity_type === 'ipc_channel');

      dangerousUnvalidatedChannels.should.deep.equal(['local-destructured-read']);
      should.exist(channelRecord);
      channelRecord.dangerous_sinks.should.deep.equal(['fs.readFileSync']);
    } finally {
      removeFixtureRoot(fixture.root);
    }
  });

  it('detects block-local fs alias destructuring dangerous sinks', () => {
    const fixture = collectPhase6({
      'main.js': `
        const { ipcMain } = require('electron');

        ipcMain.handle('local-fs-alias-destructured-read', (event, targetPath) => {
          if (targetPath) {
            const fs = require('fs');
            const { readFileSync } = fs;
            return readFileSync(targetPath, 'utf8');
          }
          return null;
        });
      `
    });

    try {
      const dangerousUnvalidatedChannels = fixture.issues
        .filter(issue => issue.id === 'IPC_DANGEROUS_SINK_NO_SENDER_VALIDATION')
        .map(issue => issue.properties.affectedChannel);
      const channelRecord = fixture.inventory.records.find(record => record.entity_type === 'ipc_channel');

      dangerousUnvalidatedChannels.should.deep.equal(['local-fs-alias-destructured-read']);
      should.exist(channelRecord);
      channelRecord.dangerous_sinks.should.deep.equal(['fs.readFileSync']);
    } finally {
      removeFixtureRoot(fixture.root);
    }
  });

  it('detects handler-local child_process alias destructuring dangerous sinks', () => {
    const fixture = collectPhase6({
      'main.js': `
        const { ipcMain } = require('electron');

        ipcMain.handle('local-child-process-alias-exec-file', (event, cmd) => {
          const cp = require('child_process');
          const { execFile } = cp;
          return execFile(cmd);
        });
      `
    });

    try {
      const dangerousUnvalidatedChannels = fixture.issues
        .filter(issue => issue.id === 'IPC_DANGEROUS_SINK_NO_SENDER_VALIDATION')
        .map(issue => issue.properties.affectedChannel);
      const channelRecord = fixture.inventory.records.find(record => record.entity_type === 'ipc_channel');

      dangerousUnvalidatedChannels.should.deep.equal(['local-child-process-alias-exec-file']);
      should.exist(channelRecord);
      channelRecord.dangerous_sinks.should.deep.equal(['child_process.execFile']);
    } finally {
      removeFixtureRoot(fixture.root);
    }
  });

  it('detects handler-local Electron shell alias destructuring dangerous sinks', () => {
    const fixture = collectPhase6({
      'main.js': `
        const { ipcMain } = require('electron');

        ipcMain.handle('local-shell-alias-open-external', (event, url) => {
          const { shell } = require('electron');
          const { openExternal } = shell;
          return openExternal(url);
        });
      `
    });

    try {
      const dangerousUnvalidatedChannels = fixture.issues
        .filter(issue => issue.id === 'IPC_DANGEROUS_SINK_NO_SENDER_VALIDATION')
        .map(issue => issue.properties.affectedChannel);
      const channelRecord = fixture.inventory.records.find(record => record.entity_type === 'ipc_channel');

      dangerousUnvalidatedChannels.should.deep.equal(['local-shell-alias-open-external']);
      should.exist(channelRecord);
      channelRecord.dangerous_sinks.should.deep.equal(['shell.openExternal']);
    } finally {
      removeFixtureRoot(fixture.root);
    }
  });

  it('detects module-level ES named builtin imports used in IPC handlers', () => {
    const fixture = collectPhase6({
      'main.ts': `
        import { ipcMain } from 'electron';
        import { execFile } from 'child_process';

        ipcMain.handle('named-import-exec', (event, cmd: string) => {
          return execFile(cmd);
        });
      `
    });

    try {
      const dangerousUnvalidatedChannels = fixture.issues
        .filter(issue => issue.id === 'IPC_DANGEROUS_SINK_NO_SENDER_VALIDATION')
        .map(issue => issue.properties.affectedChannel);
      const channelRecord = fixture.inventory.records.find(record => record.entity_type === 'ipc_channel');

      dangerousUnvalidatedChannels.should.deep.equal(['named-import-exec']);
      should.exist(channelRecord);
      channelRecord.dangerous_sinks.should.deep.equal(['child_process.execFile']);
    } finally {
      removeFixtureRoot(fixture.root);
    }
  });

  it('does not treat local named builtin shadows as dangerous sink aliases', () => {
    const fixture = collectPhase6({
      'main.js': `
        const { ipcMain } = require('electron');
        const { readFileSync } = require('fs');

        ipcMain.handle('shadowed-named-read', (event, readFileSync, targetPath) => {
          return readFileSync(targetPath);
        });
      `
    });

    try {
      fixture.issues.filter(issue => issue.id === 'IPC_DANGEROUS_SINK_NO_SENDER_VALIDATION').length.should.equal(0);

      const channelRecord = fixture.inventory.records.find(record => record.entity_type === 'ipc_channel');
      should.exist(channelRecord);
      channelRecord.dangerous_sinks.should.deep.equal([]);
    } finally {
      removeFixtureRoot(fixture.root);
    }
  });

  it('does not treat alias destructuring through local parameter shadows as dangerous sinks', () => {
    const fixture = collectPhase6({
      'main.js': `
        const { ipcMain } = require('electron');
        const fs = require('fs');

        ipcMain.handle('shadowed-fs-alias-destructure', (event, fs, targetPath) => {
          const { readFileSync } = fs;
          return readFileSync(targetPath);
        });
      `
    });

    try {
      fixture.issues.filter(issue => issue.id === 'IPC_DANGEROUS_SINK_NO_SENDER_VALIDATION').length.should.equal(0);

      const channelRecord = fixture.inventory.records.find(record => record.entity_type === 'ipc_channel');
      should.exist(channelRecord);
      channelRecord.dangerous_sinks.should.deep.equal([]);
    } finally {
      removeFixtureRoot(fixture.root);
    }
  });

  it('detects function-local contextBridge and ipcRenderer require bridge setup', () => {
    const fixture = collectPhase6({
      'preload.js': `
        function install() {
          const { contextBridge, ipcRenderer } = require('electron');

          contextBridge.exposeInMainWorld('localApi', {
            invoke(channel, payload) {
              return ipcRenderer.invoke(channel, payload);
            }
          });
        }
      `
    });

    try {
      fixture.issues.filter(issue => issue.id === 'PRELOAD_ARBITRARY_CHANNEL_FORWARD').length.should.equal(1);

      const bridgeRecord = fixture.inventory.records.find(record => record.entity_type === 'preload_bridge');
      should.exist(bridgeRecord);
      bridgeRecord.global_name.should.equal('localApi');
      bridgeRecord.arbitrary_channel_methods.should.deep.equal(['invoke']);
    } finally {
      removeFixtureRoot(fixture.root);
    }
  });

  it('treats reject-style sender validation as gating dangerous work in else branches', () => {
    const fixture = collectPhase6({
      'main.js': `
        const { ipcMain } = require('electron');
        const fs = require('fs');
        const allowedOrigins = ['https://app.example.com'];

        ipcMain.handle('else-validated-export', (event, targetPath) => {
          const origin = new URL(event.senderFrame.url).origin;
          if (!allowedOrigins.includes(origin)) {
            throw new Error('blocked');
          } else {
            return fs.readFileSync(targetPath, 'utf8');
          }
        });
      `
    });

    try {
      fixture.issues.filter(issue => issue.id === 'IPC_SENDER_VALIDATION_MISSING').length.should.equal(0);
      fixture.issues.filter(issue => issue.id === 'IPC_DANGEROUS_SINK_NO_SENDER_VALIDATION').length.should.equal(0);

      const channelRecord = fixture.inventory.records.find(record => record.entity_type === 'ipc_channel');
      should.exist(channelRecord);
      channelRecord.visible_sender_validation.should.equal(true);
      channelRecord.dangerous_sinks.should.deep.equal(['fs.readFileSync']);
    } finally {
      removeFixtureRoot(fixture.root);
    }
  });

  it('treats reject-style preload channel allowlists as gating invoke calls in else branches', () => {
    const fixture = collectPhase6({
      'preload.js': `
        const { contextBridge, ipcRenderer } = require('electron');
        const SAFE_CHANNELS = ['metrics', 'ping'];

        contextBridge.exposeInMainWorld('api', {
          invoke(channel, payload) {
            if (!SAFE_CHANNELS.includes(channel)) {
              throw new Error('blocked');
            } else {
              return ipcRenderer.invoke(channel, payload);
            }
          }
        });
      `
    });

    try {
      fixture.issues.filter(issue => issue.id === 'PRELOAD_ARBITRARY_CHANNEL_FORWARD').length.should.equal(0);

      const bridgeRecord = fixture.inventory.records.find(record => record.entity_type === 'preload_bridge');
      should.exist(bridgeRecord);
      bridgeRecord.arbitrary_channel_methods.should.deep.equal([]);
    } finally {
      removeFixtureRoot(fixture.root);
    }
  });

  it('writes bridge and IPC inventory records to structured output while keeping schema v1 finding classification stable', async function () {
    this.timeout(10000);

    const inputRoot = writeFixtureFiles({
      'preload.js': `
        const { contextBridge, ipcRenderer } = require('electron');
        const SAFE_CHANNELS = ['ping'];

        contextBridge.exposeInMainWorld('safeApi', {
          send(channel, payload) {
            if (!SAFE_CHANNELS.includes(channel)) throw new Error('blocked');
            return ipcRenderer.send(channel, payload);
          }
        });

        contextBridge.exposeInMainWorld('unsafeApi', {
          invoke(channel, payload) {
            return ipcRenderer.invoke(channel, payload);
          }
        });
      `,
      'main.js': `
        const { ipcMain } = require('electron');
        const fs = require('fs');

        ipcMain.handle('export-file', (event, targetPath) => {
          fs.writeFileSync(targetPath, 'data');
        });
      `
    });
    const outputDir = path.join(inputRoot, 'out');

    try {
      const result = await run({
        input: inputRoot,
        customScan: [],
        excludeFromScan: [],
        outputDir
      });

      const findingsDoc = parseJson(path.join(outputDir, 'findings.json'));
      const inventoryDoc = parseJson(path.join(outputDir, 'inventory.json'));
      const preloadBridgeRecords = inventoryDoc.records.filter(record => record.entity_type === 'preload_bridge');
      const ipcChannelRecords = inventoryDoc.records.filter(record => record.entity_type === 'ipc_channel');
      const arbitraryForwardFinding = findingsDoc.findings.find(finding => finding.check_id === 'PRELOAD_ARBITRARY_CHANNEL_FORWARD');
      const dangerousIpcFinding = findingsDoc.findings.find(finding => finding.check_id === 'IPC_DANGEROUS_SINK_NO_SENDER_VALIDATION');
      const linkedForwardFinding = findingsDoc.findings.find(finding => finding.check_id === 'IPC_ARBITRARY_FORWARDING_TO_DANGEROUS_CHANNEL');

      result.schemaV1.inventory.records.some(record => record.entity_type === 'preload_bridge').should.equal(true);
      result.schemaV1.inventory.records.some(record => record.entity_type === 'ipc_channel').should.equal(true);
      preloadBridgeRecords.map(record => record.global_name).sort().should.deep.equal(['safeApi', 'unsafeApi']);
      ipcChannelRecords.some(record => record.channel === 'export-file').should.equal(true);

      should.exist(arbitraryForwardFinding);
      should.exist(dangerousIpcFinding);
      should.exist(linkedForwardFinding);
      arbitraryForwardFinding.classification.should.equal('finding');
      arbitraryForwardFinding.severity.should.equal('high');
      arbitraryForwardFinding.electron_component.should.equal('preload');
      dangerousIpcFinding.classification.should.equal('finding');
      dangerousIpcFinding.severity.should.equal('high');
      dangerousIpcFinding.affected_window_or_channel.should.equal('export-file');
      linkedForwardFinding.trust_boundary.should.equal('renderer_to_main_ipc');
    } finally {
      removeFixtureRoot(inputRoot);
    }
  });

  it('recognizes TypeScript object properties and methods in preload bridge exposures', () => {
    const fixture = collectPhase6({
      'preload.ts': `
        import { contextBridge, ipcRenderer, shell } from 'electron';

        contextBridge.exposeInMainWorld('typedApi', {
          ipc: ipcRenderer,
          invoke(channel: string, payload: unknown) {
            return ipcRenderer.invoke(channel, payload);
          },
          open: (url: string) => shell.openExternal(url)
        });
      `
    });

    try {
      fixture.issues.filter(issue => issue.id === 'PRELOAD_RAW_IPC_EXPOSURE').length.should.equal(1);
      fixture.issues.filter(issue => issue.id === 'PRELOAD_ARBITRARY_CHANNEL_FORWARD').length.should.equal(1);
      fixture.issues.filter(issue => issue.id === 'PRELOAD_DANGEROUS_API_WRAPPER').length.should.equal(1);

      const bridgeRecord = fixture.inventory.records.find(record => record.entity_type === 'preload_bridge');
      should.exist(bridgeRecord);
      bridgeRecord.methods.sort().should.deep.equal(['invoke', 'ipc', 'open']);
      bridgeRecord.raw_ipc_exposed.should.equal(true);
      bridgeRecord.arbitrary_channel_methods.should.deep.equal(['invoke']);
      bridgeRecord.dangerous_wrappers.should.deep.equal(['open: shell.openExternal']);
    } finally {
      removeFixtureRoot(fixture.root);
    }
  });

  it('detects preload Electron shell alias destructuring dangerous wrappers', () => {
    const fixture = collectPhase6({
      'preload.js': `
        const { contextBridge, shell } = require('electron');
        const { openExternal } = shell;

        contextBridge.exposeInMainWorld('nativeApi', {
          open(url) {
            return openExternal(url);
          }
        });
      `
    });

    try {
      fixture.issues.filter(issue => issue.id === 'PRELOAD_DANGEROUS_API_WRAPPER').length.should.equal(1);

      const bridgeRecord = fixture.inventory.records.find(record => record.entity_type === 'preload_bridge');
      should.exist(bridgeRecord);
      bridgeRecord.dangerous_wrappers.should.deep.equal(['open: shell.openExternal']);
    } finally {
      removeFixtureRoot(fixture.root);
    }
  });

  it('resolves TypeScript module-level preload bridge object aliases', () => {
    const fixture = collectPhase6({
      'preload.ts': `
        import { contextBridge, ipcRenderer, shell } from 'electron';

        const typedApi = {
          ipc: ipcRenderer,
          invoke(channel: string, payload: unknown) {
            return ipcRenderer.invoke(channel, payload);
          },
          open: (url: string) => shell.openExternal(url)
        };

        contextBridge.exposeInMainWorld('typedApi', typedApi);
      `
    });

    try {
      fixture.issues.filter(issue => issue.id === 'PRELOAD_RAW_IPC_EXPOSURE').length.should.equal(1);
      fixture.issues.filter(issue => issue.id === 'PRELOAD_ARBITRARY_CHANNEL_FORWARD').length.should.equal(1);
      fixture.issues.filter(issue => issue.id === 'PRELOAD_DANGEROUS_API_WRAPPER').length.should.equal(1);

      const bridgeRecord = fixture.inventory.records.find(record => record.entity_type === 'preload_bridge');
      should.exist(bridgeRecord);
      bridgeRecord.methods.sort().should.deep.equal(['invoke', 'ipc', 'open']);
      bridgeRecord.raw_ipc_exposed.should.equal(true);
      bridgeRecord.arbitrary_channel_methods.should.deep.equal(['invoke']);
      bridgeRecord.dangerous_wrappers.should.deep.equal(['open: shell.openExternal']);
    } finally {
      removeFixtureRoot(fixture.root);
    }
  });

  it('resolves handler-local sink aliases and new Set allowlists inside sender validation guards', () => {
    const fixture = collectPhase6({
      'main.js': `
        const { ipcMain } = require('electron');
        const fs = require('fs');

        ipcMain.handle('alias-export', (event, targetPath) => {
          const origin = new URL(event.senderFrame.url).origin;
          const allowedOrigins = new Set(['https://app.example.com']);
          if (!allowedOrigins.has(origin)) throw new Error('blocked');
          const write = fs.writeFileSync;
          write(targetPath, 'data');
        });
      `,
      'main.ts': `
        import { ipcMain } from 'electron';
        import fs from 'fs';

        ipcMain.handle('ts-alias-export', (event, targetPath: string) => {
          const origin = new URL(event.senderFrame.url).origin;
          const allowedOrigins = new Set(['https://app.example.com']);
          if (!allowedOrigins.has(origin)) throw new Error('blocked');
          const write = fs.writeFileSync;
          write(targetPath, 'data');
        });
      `
    });

    try {
      fixture.issues.filter(issue => issue.id === 'IPC_SENDER_VALIDATION_MISSING').length.should.equal(0);
      fixture.issues.filter(issue => issue.id === 'IPC_DANGEROUS_SINK_NO_SENDER_VALIDATION').length.should.equal(0);

      const channelRecords = fixture.inventory.records.filter(record => record.entity_type === 'ipc_channel');
      const jsChannelRecord = channelRecords.find(record => record.channel === 'alias-export');
      const tsChannelRecord = channelRecords.find(record => record.channel === 'ts-alias-export');
      should.exist(jsChannelRecord);
      should.exist(tsChannelRecord);
      jsChannelRecord.visible_sender_validation.should.equal(true);
      tsChannelRecord.visible_sender_validation.should.equal(true);
      jsChannelRecord.sender_validation_evidence.should.deep.equal(['sender URL/origin checked against allowlist', 'sender origin alias']);
      tsChannelRecord.sender_validation_evidence.should.deep.equal(['sender URL/origin checked against allowlist', 'sender origin alias']);
      jsChannelRecord.dangerous_sinks.should.deep.equal(['fs.writeFileSync']);
      tsChannelRecord.dangerous_sinks.should.deep.equal(['fs.writeFileSync']);
    } finally {
      removeFixtureRoot(fixture.root);
    }
  });

  it('resolves TypeScript module-level sender allowlists for validated non-dangerous IPC handlers', () => {
    const fixture = collectPhase6({
      'main.ts': `
        import { ipcMain } from 'electron';

        const allowedOrigins = new Set(['https://app.example.com']);

        ipcMain.handle('validated-ping', (event, payload: string) => {
          const origin = new URL(event.senderFrame.url).origin;
          if (allowedOrigins.has(origin)) {
            return payload;
          }
          throw new Error('blocked');
        });
      `
    });

    try {
      fixture.issues.filter(issue => issue.id === 'IPC_SENDER_VALIDATION_MISSING').length.should.equal(0);
      fixture.issues.filter(issue => issue.id === 'IPC_DANGEROUS_SINK_NO_SENDER_VALIDATION').length.should.equal(0);

      const channelRecord = fixture.inventory.records.find(record => record.entity_type === 'ipc_channel');
      should.exist(channelRecord);
      channelRecord.channel.should.equal('validated-ping');
      channelRecord.visible_sender_validation.should.equal(true);
      channelRecord.sender_validation_evidence.should.deep.equal(['sender URL/origin checked against allowlist', 'sender origin alias']);
      channelRecord.dangerous_sinks.should.deep.equal([]);
    } finally {
      removeFixtureRoot(fixture.root);
    }
  });

  it('does not treat unused or non-gating sender validation expressions as visible validation', () => {
    const fixture = collectPhase6({
      'main.js': `
        const { ipcMain } = require('electron');
        const fs = require('fs');
        const allowedOrigins = ['https://app.example.com'];
        const devMode = true;

        ipcMain.handle('unused-validation', (event, targetPath) => {
          const origin = new URL(event.senderFrame.url).origin;
          allowedOrigins.includes(origin);
          return fs.readFileSync(targetPath, 'utf8');
        });

        ipcMain.handle('log-only-validation', (event, targetPath) => {
          const origin = new URL(event.senderFrame.url).origin;
          if (!allowedOrigins.includes(origin)) console.warn('blocked');
          return fs.readFileSync(targetPath, 'utf8');
        });

        ipcMain.handle('or-dev-validation', (event, targetPath) => {
          const origin = new URL(event.senderFrame.url).origin;
          if (allowedOrigins.includes(origin) || devMode) {
            return fs.readFileSync(targetPath, 'utf8');
          }
        });
      `
    });

    try {
      const missingValidationChannels = fixture.issues
        .filter(issue => issue.id === 'IPC_SENDER_VALIDATION_MISSING')
        .map(issue => issue.properties.affectedChannel)
        .sort();
      const dangerousUnvalidatedChannels = fixture.issues
        .filter(issue => issue.id === 'IPC_DANGEROUS_SINK_NO_SENDER_VALIDATION')
        .map(issue => issue.properties.affectedChannel)
        .sort();
      missingValidationChannels.should.deep.equal(['log-only-validation', 'or-dev-validation', 'unused-validation']);
      dangerousUnvalidatedChannels.should.deep.equal(['log-only-validation', 'or-dev-validation', 'unused-validation']);
    } finally {
      removeFixtureRoot(fixture.root);
    }
  });

  it('does not treat non-gating sender validation branches as visible validation', () => {
    const fixture = collectPhase6({
      'main.js': `
        const { ipcMain } = require('electron');
        const fs = require('fs');
        const allowedOrigins = ['https://app.example.com'];

        ipcMain.handle('branch-only-validation', (event, targetPath) => {
          const origin = new URL(event.senderFrame.url).origin;
          if (allowedOrigins.includes(origin)) {
            console.log('allowed renderer');
          }
          return fs.readFileSync(targetPath, 'utf8');
        });

        ipcMain.handle('permissive-validation', (event, targetPath) => {
          const origin = new URL(event.senderFrame.url).origin;
          if (allowedOrigins.includes(origin)) return;
          return fs.readFileSync(targetPath, 'utf8');
        });
      `
    });

    try {
      const missingValidationChannels = fixture.issues
        .filter(issue => issue.id === 'IPC_SENDER_VALIDATION_MISSING')
        .map(issue => issue.properties.affectedChannel)
        .sort();
      const dangerousUnvalidatedChannels = fixture.issues
        .filter(issue => issue.id === 'IPC_DANGEROUS_SINK_NO_SENDER_VALIDATION')
        .map(issue => issue.properties.affectedChannel)
        .sort();
      const channelRecords = fixture.inventory.records
        .filter(record => record.entity_type === 'ipc_channel')
        .sort((left, right) => left.channel.localeCompare(right.channel));

      missingValidationChannels.should.deep.equal(['branch-only-validation', 'permissive-validation']);
      dangerousUnvalidatedChannels.should.deep.equal(['branch-only-validation', 'permissive-validation']);
      channelRecords.map(record => record.visible_sender_validation).should.deep.equal([false, false]);
    } finally {
      removeFixtureRoot(fixture.root);
    }
  });

  it('does not treat block-local sender alias shadows as visible validation', () => {
    const fixture = collectPhase6({
      'main.js': `
        const { ipcMain } = require('electron');
        const fs = require('fs');
        const allowedOrigins = ['https://app.example.com'];

        ipcMain.handle('block-local-shadowed-origin', (event, targetPath) => {
          const origin = new URL(event.senderFrame.url).origin;
          {
            const origin = 'https://app.example.com';
            if (!allowedOrigins.includes(origin)) throw new Error('blocked');
            return fs.readFileSync(targetPath, 'utf8');
          }
        });
      `
    });

    try {
      const missingValidationChannels = fixture.issues
        .filter(issue => issue.id === 'IPC_SENDER_VALIDATION_MISSING')
        .map(issue => issue.properties.affectedChannel);
      const dangerousUnvalidatedChannels = fixture.issues
        .filter(issue => issue.id === 'IPC_DANGEROUS_SINK_NO_SENDER_VALIDATION')
        .map(issue => issue.properties.affectedChannel);
      const channelRecord = fixture.inventory.records.find(record => record.entity_type === 'ipc_channel');

      missingValidationChannels.should.deep.equal(['block-local-shadowed-origin']);
      dangerousUnvalidatedChannels.should.deep.equal(['block-local-shadowed-origin']);
      should.exist(channelRecord);
      channelRecord.visible_sender_validation.should.equal(false);
      channelRecord.dangerous_sinks.should.deep.equal(['fs.readFileSync']);
    } finally {
      removeFixtureRoot(fixture.root);
    }
  });

  it('does not treat non-gating preload channel allowlist branches as validation', () => {
    const fixture = collectPhase6({
      'preload.js': `
        const { contextBridge, ipcRenderer } = require('electron');
        const SAFE_CHANNELS = ['metrics', 'ping'];

        contextBridge.exposeInMainWorld('unsafeApi', {
          branchOnly(channel, payload) {
            if (SAFE_CHANNELS.includes(channel)) {
              console.log('allowed channel');
            }
            return ipcRenderer.invoke(channel, payload);
          },
          permissive(channel, payload) {
            if (SAFE_CHANNELS.includes(channel)) return;
            return ipcRenderer.send(channel, payload);
          }
        });
      `
    });

    try {
      fixture.issues.filter(issue => issue.id === 'PRELOAD_ARBITRARY_CHANNEL_FORWARD').length.should.equal(1);

      const bridgeRecord = fixture.inventory.records.find(record => record.entity_type === 'preload_bridge');
      should.exist(bridgeRecord);
      bridgeRecord.arbitrary_channel_methods.should.deep.equal(['branchOnly', 'permissive']);
    } finally {
      removeFixtureRoot(fixture.root);
    }
  });

  it('does not treat conditional && validation guards as safe gating', () => {
    const fixture = collectPhase6({
      'preload.js': `
        const { contextBridge, ipcRenderer } = require('electron');
        const SAFE_CHANNELS = ['metrics', 'ping'];
        const enforceChannels = false;

        contextBridge.exposeInMainWorld('api', {
          guardedByFlag(channel, payload) {
            if (!SAFE_CHANNELS.includes(channel) && enforceChannels) throw new Error('blocked');
            return ipcRenderer.invoke(channel, payload);
          }
        });
      `,
      'main.js': `
        const { ipcMain } = require('electron');
        const fs = require('fs');
        const allowedOrigins = ['https://app.example.com'];
        const enforceOrigins = false;

        ipcMain.handle('conditional-validation', (event, targetPath) => {
          const origin = new URL(event.senderFrame.url).origin;
          if (!allowedOrigins.includes(origin) && enforceOrigins) throw new Error('blocked');
          return fs.readFileSync(targetPath, 'utf8');
        });
      `
    });

    try {
      const missingValidationChannels = fixture.issues
        .filter(issue => issue.id === 'IPC_SENDER_VALIDATION_MISSING')
        .map(issue => issue.properties.affectedChannel);
      const dangerousUnvalidatedChannels = fixture.issues
        .filter(issue => issue.id === 'IPC_DANGEROUS_SINK_NO_SENDER_VALIDATION')
        .map(issue => issue.properties.affectedChannel);

      fixture.issues.filter(issue => issue.id === 'PRELOAD_ARBITRARY_CHANNEL_FORWARD').length.should.equal(1);
      missingValidationChannels.should.deep.equal(['conditional-validation']);
      dangerousUnvalidatedChannels.should.deep.equal(['conditional-validation']);

      const bridgeRecord = fixture.inventory.records.find(record => record.entity_type === 'preload_bridge');
      const channelRecord = fixture.inventory.records.find(record => record.entity_type === 'ipc_channel');
      bridgeRecord.arbitrary_channel_methods.should.deep.equal(['guardedByFlag']);
      channelRecord.visible_sender_validation.should.equal(false);
    } finally {
      removeFixtureRoot(fixture.root);
    }
  });

  it('does not treat switch channel cases as preload channel validation', () => {
    const fixture = collectPhase6({
      'preload.js': `
        const { contextBridge, ipcRenderer } = require('electron');

        contextBridge.exposeInMainWorld('api', {
          invoke(channel, payload) {
            switch (channel) {
              case 'metrics':
              case 'ping':
                break;
              default:
                break;
            }
            return ipcRenderer.invoke(channel, payload);
          }
        });
      `
    });

    try {
      fixture.issues.filter(issue => issue.id === 'PRELOAD_ARBITRARY_CHANNEL_FORWARD').length.should.equal(1);

      const bridgeRecord = fixture.inventory.records.find(record => record.entity_type === 'preload_bridge');
      should.exist(bridgeRecord);
      bridgeRecord.arbitrary_channel_methods.should.deep.equal(['invoke']);
    } finally {
      removeFixtureRoot(fixture.root);
    }
  });

  it('flags preload arbitrary channel forwards that run before channel allowlist validation', () => {
    const fixture = collectPhase6({
      'preload.js': `
        const { contextBridge, ipcRenderer } = require('electron');
        const SAFE_CHANNELS = ['metrics', 'ping'];

        contextBridge.exposeInMainWorld('api', {
          guardedInvoke(channel, payload) {
            if (!SAFE_CHANNELS.includes(channel)) throw new Error('blocked');
            return ipcRenderer.invoke(channel, payload);
          },
          lateInvoke(channel, payload) {
            const result = ipcRenderer.invoke(channel, payload);
            if (!SAFE_CHANNELS.includes(channel)) throw new Error('blocked');
            return result;
          }
        });
      `
    });

    try {
      fixture.issues.filter(issue => issue.id === 'PRELOAD_ARBITRARY_CHANNEL_FORWARD').length.should.equal(1);

      const bridgeRecord = fixture.inventory.records.find(record => record.entity_type === 'preload_bridge');
      should.exist(bridgeRecord);
      bridgeRecord.arbitrary_channel_methods.should.deep.equal(['lateInvoke']);
    } finally {
      removeFixtureRoot(fixture.root);
    }
  });

  it('flags preload arbitrary channel forwards that run before positive-form channel allowlists with else throw', () => {
    const fixture = collectPhase6({
      'preload.js': `
        const { contextBridge, ipcRenderer } = require('electron');
        const SAFE_CHANNELS = ['metrics', 'ping'];

        contextBridge.exposeInMainWorld('api', {
          latePositiveInvoke(channel, payload) {
            const result = ipcRenderer.invoke(channel, payload);
            if (SAFE_CHANNELS.includes(channel)) {
              return result;
            } else {
              throw new Error('blocked');
            }
          }
        });
      `
    });

    try {
      fixture.issues.filter(issue => issue.id === 'PRELOAD_ARBITRARY_CHANNEL_FORWARD').length.should.equal(1);

      const bridgeRecord = fixture.inventory.records.find(record => record.entity_type === 'preload_bridge');
      should.exist(bridgeRecord);
      bridgeRecord.arbitrary_channel_methods.should.deep.equal(['latePositiveInvoke']);
    } finally {
      removeFixtureRoot(fixture.root);
    }
  });

  it('resolves Electron namespace aliases for preload forwards and IPC dangerous sinks', () => {
    const fixture = collectPhase6({
      'preload.js': `
        const electron = require('electron');
        electron.contextBridge.exposeInMainWorld('api', {
          invoke(channel, payload) {
            return electron.ipcRenderer.invoke(channel, payload);
          }
        });
      `,
      'main.js': `
        const electron = require('electron');
        const { ipcMain, shell } = electron;

        ipcMain.handle('open', (event, url) => {
          return shell.openExternal(url);
        });
      `
    });

    try {
      fixture.issues.filter(issue => issue.id === 'PRELOAD_ARBITRARY_CHANNEL_FORWARD').length.should.equal(1);

      const dangerousUnvalidatedChannels = fixture.issues
        .filter(issue => issue.id === 'IPC_DANGEROUS_SINK_NO_SENDER_VALIDATION')
        .map(issue => issue.properties.affectedChannel);
      const bridgeRecord = fixture.inventory.records.find(record => record.entity_type === 'preload_bridge');
      const channelRecord = fixture.inventory.records.find(record => record.entity_type === 'ipc_channel');

      dangerousUnvalidatedChannels.should.deep.equal(['open']);
      should.exist(bridgeRecord);
      bridgeRecord.arbitrary_channel_methods.should.deep.equal(['invoke']);
      should.exist(channelRecord);
      channelRecord.dangerous_sinks.should.deep.equal(['shell.openExternal']);
    } finally {
      removeFixtureRoot(fixture.root);
    }
  });

  it('honors local builtin alias shadowing while detecting handler-local requires', () => {
    const fixture = collectPhase6({
      'preload.js': `
        const { contextBridge, ipcRenderer } = require('electron');

        contextBridge.exposeInMainWorld('api', {
          invoke(channel, payload) {
            const ipcRenderer = { invoke() { return 'local'; } };
            return ipcRenderer.invoke(channel, payload);
          }
        });
      `,
      'main.js': `
        const { ipcMain } = require('electron');
        const fs = require('fs');

        ipcMain.handle('shadowed-fs-param', (event, fs, targetPath) => {
          const origin = new URL(event.senderFrame.url).origin;
          if (origin !== 'https://app.example.com') throw new Error('blocked');
          return fs.readFileSync(targetPath, 'utf8');
        });

        ipcMain.handle('shadowed-fs-local', (event, targetPath) => {
          const origin = new URL(event.senderFrame.url).origin;
          if (origin !== 'https://app.example.com') throw new Error('blocked');
          const fs = { readFileSync() { return 'local'; } };
          return fs.readFileSync(targetPath, 'utf8');
        });

        ipcMain.handle('local-require-fs', (event, targetPath) => {
          const fs = require('fs');
          return fs.readFileSync(targetPath, 'utf8');
        });
      `
    });

    try {
      const missingValidationChannels = fixture.issues
        .filter(issue => issue.id === 'IPC_SENDER_VALIDATION_MISSING')
        .map(issue => issue.properties.affectedChannel);
      const dangerousUnvalidatedChannels = fixture.issues
        .filter(issue => issue.id === 'IPC_DANGEROUS_SINK_NO_SENDER_VALIDATION')
        .map(issue => issue.properties.affectedChannel);
      const channelRecords = fixture.inventory.records
        .filter(record => record.entity_type === 'ipc_channel')
        .sort((left, right) => left.channel.localeCompare(right.channel));

      fixture.issues.filter(issue => issue.id === 'PRELOAD_ARBITRARY_CHANNEL_FORWARD').length.should.equal(0);
      missingValidationChannels.should.deep.equal(['local-require-fs']);
      dangerousUnvalidatedChannels.should.deep.equal(['local-require-fs']);
      channelRecords.find(record => record.channel === 'local-require-fs').dangerous_sinks.should.deep.equal(['fs.readFileSync']);
      channelRecords.find(record => record.channel === 'shadowed-fs-local').dangerous_sinks.should.deep.equal([]);
      channelRecords.find(record => record.channel === 'shadowed-fs-param').dangerous_sinks.should.deep.equal([]);
    } finally {
      removeFixtureRoot(fixture.root);
    }
  });

  it('does not let block-local aliases suppress later module-level dangerous sinks', () => {
    const fixture = collectPhase6({
      'main.js': `
        const { ipcMain } = require('electron');
        const fs = require('fs');

        ipcMain.handle('block-local-shadow', (event, targetPath) => {
          if (targetPath) {
            const fs = { writeFileSync() { return 'local'; } };
          }

          fs.writeFileSync(targetPath, 'data');
        });
      `
    });

    try {
      const dangerousUnvalidatedChannels = fixture.issues
        .filter(issue => issue.id === 'IPC_DANGEROUS_SINK_NO_SENDER_VALIDATION')
        .map(issue => issue.properties.affectedChannel);
      const channelRecord = fixture.inventory.records.find(record => record.entity_type === 'ipc_channel');

      dangerousUnvalidatedChannels.should.deep.equal(['block-local-shadow']);
      should.exist(channelRecord);
      channelRecord.dangerous_sinks.should.deep.equal(['fs.writeFileSync']);
    } finally {
      removeFixtureRoot(fixture.root);
    }
  });

  it('flags validation after handler-local destructured builtin aliases', () => {
    const fixture = collectPhase6({
      'main.js': `
        const { ipcMain } = require('electron');
        const allowedOrigins = ['https://app.example.com'];

        ipcMain.handle('prior-destructured', (event, targetPath) => {
          const origin = new URL(event.senderFrame.url).origin;
          const { readFileSync } = require('fs');
          readFileSync(targetPath, 'utf8');
          if (allowedOrigins.includes(origin)) {
            return 'ok';
          } else {
            throw new Error('blocked');
          }
        });
      `
    });

    try {
      const missingValidationChannels = fixture.issues
        .filter(issue => issue.id === 'IPC_SENDER_VALIDATION_MISSING')
        .map(issue => issue.properties.affectedChannel);
      const dangerousUnvalidatedChannels = fixture.issues
        .filter(issue => issue.id === 'IPC_DANGEROUS_SINK_NO_SENDER_VALIDATION')
        .map(issue => issue.properties.affectedChannel);
      const channelRecord = fixture.inventory.records.find(record => record.entity_type === 'ipc_channel');

      missingValidationChannels.should.deep.equal(['prior-destructured']);
      dangerousUnvalidatedChannels.should.deep.equal(['prior-destructured']);
      should.exist(channelRecord);
      channelRecord.visible_sender_validation.should.equal(false);
      channelRecord.dangerous_sinks.should.deep.equal(['fs.readFileSync']);
    } finally {
      removeFixtureRoot(fixture.root);
    }
  });

  it('detects block-local fs requires at dangerous sink call sites', () => {
    const fixture = collectPhase6({
      'main.js': `
        const { ipcMain } = require('electron');

        ipcMain.handle('block-local-require-fs', (event, targetPath) => {
          if (targetPath) {
            const fs = require('fs');
            return fs.readFileSync(targetPath, 'utf8');
          }
        });
      `
    });

    try {
      const dangerousUnvalidatedChannels = fixture.issues
        .filter(issue => issue.id === 'IPC_DANGEROUS_SINK_NO_SENDER_VALIDATION')
        .map(issue => issue.properties.affectedChannel);
      const channelRecord = fixture.inventory.records.find(record => record.entity_type === 'ipc_channel');

      dangerousUnvalidatedChannels.should.deep.equal(['block-local-require-fs']);
      should.exist(channelRecord);
      channelRecord.dangerous_sinks.should.deep.equal(['fs.readFileSync']);
    } finally {
      removeFixtureRoot(fixture.root);
    }
  });

  it('does not flag block-local fs shadows at dangerous sink call sites', () => {
    const fixture = collectPhase6({
      'main.js': `
        const { ipcMain } = require('electron');
        const fs = require('fs');

        ipcMain.handle('block-local-shadow-fs', (event, targetPath) => {
          if (targetPath) {
            const fs = { writeFileSync() { return 'local'; } };
            fs.writeFileSync(targetPath, 'data');
          }
        });
      `
    });

    try {
      fixture.issues.filter(issue => issue.id === 'IPC_DANGEROUS_SINK_NO_SENDER_VALIDATION').length.should.equal(0);

      const channelRecord = fixture.inventory.records.find(record => record.entity_type === 'ipc_channel');
      should.exist(channelRecord);
      channelRecord.dangerous_sinks.should.deep.equal([]);
    } finally {
      removeFixtureRoot(fixture.root);
    }
  });

  it('honors handler-local function declaration shadows for fs and require', () => {
    const fixture = collectPhase6({
      'main.js': `
        const { ipcMain } = require('electron');
        const fs = require('fs');

        ipcMain.handle('shadowed-function-fs', (event, targetPath) => {
          function fs() {}
          return fs.writeFileSync(targetPath, 'data');
        });

        ipcMain.handle('shadowed-function-require', (event, targetPath) => {
          function require() {
            return { readFileSync() { return 'local'; } };
          }
          const localFs = require('fs');
          return localFs.readFileSync(targetPath, 'utf8');
        });
      `
    });

    try {
      fixture.issues.filter(issue => issue.id === 'IPC_DANGEROUS_SINK_NO_SENDER_VALIDATION').length.should.equal(0);

      const channelRecords = fixture.inventory.records
        .filter(record => record.entity_type === 'ipc_channel')
        .sort((left, right) => left.channel.localeCompare(right.channel));
      channelRecords.map(record => record.channel).should.deep.equal(['shadowed-function-fs', 'shadowed-function-require']);
      channelRecords.forEach(record => {
        record.dangerous_sinks.should.deep.equal([]);
      });
    } finally {
      removeFixtureRoot(fixture.root);
    }
  });

  it('does not classify require calls as real Node require when handlers shadow require', () => {
    const fixture = collectPhase6({
      'main.js': `
        const { ipcMain } = require('electron');

        ipcMain.handle('shadowed-require-param', (event, require, targetPath) => {
          const fs = require('fs');
          return fs.readFileSync(targetPath, 'utf8');
        });

        ipcMain.handle('shadowed-require-local', (event, targetPath) => {
          const require = () => ({ readFileSync() { return 'local'; } });
          const fs = require('fs');
          return fs.readFileSync(targetPath, 'utf8');
        });
      `
    });

    try {
      fixture.issues.filter(issue => issue.id === 'IPC_DANGEROUS_SINK_NO_SENDER_VALIDATION').length.should.equal(0);

      const channelRecords = fixture.inventory.records
        .filter(record => record.entity_type === 'ipc_channel')
        .sort((left, right) => left.channel.localeCompare(right.channel));
      channelRecords.map(record => record.channel).should.deep.equal(['shadowed-require-local', 'shadowed-require-param']);
      channelRecords.forEach(record => {
        record.dangerous_sinks.should.deep.equal([]);
      });
    } finally {
      removeFixtureRoot(fixture.root);
    }
  });

  it('does not resolve module-level aliases through function parameter shadowing', () => {
    const fixture = collectPhase6({
      'preload.js': `
        const { contextBridge, ipcRenderer } = require('electron');
        const channel = 'safe-literal';

        contextBridge.exposeInMainWorld('api', {
          invoke(channel, payload) {
            return ipcRenderer.invoke(channel, payload);
          }
        });
      `,
      'main.js': `
        const { ipcMain } = require('electron');
        const fs = require('fs');
        const allowedOrigins = ['https://app.example.com'];

        ipcMain.handle('shadowed-allowlist', (event, allowedOrigins, targetPath) => {
          const origin = new URL(event.senderFrame.url).origin;
          if (!allowedOrigins.includes(origin)) throw new Error('blocked');
          return fs.readFileSync(targetPath, 'utf8');
        });
      `
    });

    try {
      fixture.issues.filter(issue => issue.id === 'PRELOAD_ARBITRARY_CHANNEL_FORWARD').length.should.equal(1);

      const missingValidationChannels = fixture.issues
        .filter(issue => issue.id === 'IPC_SENDER_VALIDATION_MISSING')
        .map(issue => issue.properties.affectedChannel);
      const dangerousUnvalidatedChannels = fixture.issues
        .filter(issue => issue.id === 'IPC_DANGEROUS_SINK_NO_SENDER_VALIDATION')
        .map(issue => issue.properties.affectedChannel);
      missingValidationChannels.should.deep.equal(['shadowed-allowlist']);
      dangerousUnvalidatedChannels.should.deep.equal(['shadowed-allowlist']);

      const bridgeRecord = fixture.inventory.records.find(record => record.entity_type === 'preload_bridge');
      const channelRecord = fixture.inventory.records.find(record => record.entity_type === 'ipc_channel');
      bridgeRecord.arbitrary_channel_methods.should.deep.equal(['invoke']);
      bridgeRecord.literal_ipc_channels.should.deep.equal([]);
      channelRecord.visible_sender_validation.should.equal(false);
    } finally {
      removeFixtureRoot(fixture.root);
    }
  });

  it('does not classify harmless keyword-only identifiers as dangerous IPC sinks', () => {
    const fixture = collectPhase6({
      'main.js': `
        const { ipcMain } = require('electron');

        ipcMain.handle('session-label', (event, sessionLabel) => {
          const displayLabel = sessionLabel.trim();
          return { displayLabel };
        });
      `
    });

    try {
      fixture.issues.filter(issue => issue.id === 'IPC_SENDER_VALIDATION_MISSING').length.should.equal(1);
      fixture.issues.filter(issue => issue.id === 'IPC_DANGEROUS_SINK_NO_SENDER_VALIDATION').length.should.equal(0);

      const channelRecord = fixture.inventory.records.find(record => record.entity_type === 'ipc_channel');
      should.exist(channelRecord);
      channelRecord.dangerous_sinks.should.deep.equal([]);
    } finally {
      removeFixtureRoot(fixture.root);
    }
  });

  it('honors Phase 6 eng-disable comments on exposed property and dangerous sink lines', async function () {
    this.timeout(10000);

    const inputRoot = writeFixtureFiles({
      'preload.js': `
        const { contextBridge, ipcRenderer } = require('electron');

        contextBridge.exposeInMainWorld('unsafeApi', {
          ipc: ipcRenderer, // eng-disable PRELOAD_RAW_IPC_EXPOSURE
          send(channel, payload) {
            return ipcRenderer.invoke(channel, payload);
          }
        });
      `,
      'main.js': `
        const { ipcMain } = require('electron');
        const fs = require('fs');

        ipcMain.handle('write-file', (event, targetPath) => {
          fs.writeFileSync(targetPath, 'data'); // eng-disable IPC_DANGEROUS_SINK_NO_SENDER_VALIDATION
        });
      `
    });

    try {
      const result = await run({
        input: inputRoot,
        customScan: [],
        excludeFromScan: []
      });

      result.issues.some(issue => issue.id === 'PRELOAD_RAW_IPC_EXPOSURE').should.equal(false);
      result.issues.some(issue => issue.id === 'IPC_DANGEROUS_SINK_NO_SENDER_VALIDATION').should.equal(false);
      result.issues.some(issue => issue.id === 'PRELOAD_ARBITRARY_CHANNEL_FORWARD').should.equal(true);
      result.issues.some(issue => issue.id === 'IPC_SENDER_VALIDATION_MISSING').should.equal(true);
    } finally {
      removeFixtureRoot(inputRoot);
    }
  });

  it('applies Phase 6 customScan, excludeFromScan, and eng-disable compatibility', async function () {
    this.timeout(10000);

    const inputRoot = writeFixtureFiles({
      'preload.js': `
        const { contextBridge, ipcRenderer, process } = require('electron');
        contextBridge.exposeInMainWorld('unsafeApi', {
          ipc: ipcRenderer, /* eng-disable PRELOAD_RAW_IPC_EXPOSURE */
          proc: process,
          send(channel, payload) {
            return ipcRenderer.invoke(channel, payload);
          }
        });
      `
    });

    try {
      const customResult = await run({
        input: inputRoot,
        customScan: ['PreloadArbitraryChannelForwardCheck'],
        excludeFromScan: []
      });
      customResult.issues.map(issue => issue.id).should.deep.equal(['PRELOAD_ARBITRARY_CHANNEL_FORWARD']);

      const excludedResult = await run({
        input: inputRoot,
        customScan: [],
        excludeFromScan: ['PRELOAD_NODE_PRIMITIVE_EXPOSURE']
      });
      excludedResult.issues.some(issue => issue.id === 'PRELOAD_RAW_IPC_EXPOSURE').should.equal(false);
      excludedResult.issues.some(issue => issue.id === 'PRELOAD_NODE_PRIMITIVE_EXPOSURE').should.equal(false);
      excludedResult.issues.some(issue => issue.id === 'PRELOAD_ARBITRARY_CHANNEL_FORWARD').should.equal(true);
    } finally {
      removeFixtureRoot(inputRoot);
    }
  });
});
