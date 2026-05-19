import fs from 'fs';
import os from 'os';
import path from 'path';

import run from '../src/runner';

let chai = require('chai');
let should = chai.should();

function writeFixtureFiles(files) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'electro-phase789-'));

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

function parseJsonl(file) {
  const body = fs.readFileSync(file, 'utf8').trim();
  return body ? body.split('\n').map(line => JSON.parse(line)) : [];
}

describe('Phase 7 navigation, protocol, permission, and CSP audit', () => {
  it('emits deterministic checks and inventory for unsafe navigation, protocol, permission, and CSP patterns', async function () {
    this.timeout(10000);

    const root = writeFixtureFiles({
      'main.js': `
        const { BrowserWindow, protocol, session, shell, net } = require('electron');
        const path = require('path');
        const appRoot = __dirname;

        const safeWin = new BrowserWindow({});
        safeWin.webContents.setWindowOpenHandler(({ url }) => {
          const parsed = new URL(url);
          if (parsed.protocol === 'https:' && ['app.example.com'].includes(parsed.hostname)) {
            return { action: 'allow' };
          }
          return { action: 'deny' };
        });

        const unsafeWin = new BrowserWindow({});
        unsafeWin.webContents.setWindowOpenHandler((details) => {
          shell.openExternal(details.url);
          return { action: 'allow' };
        });

        protocol.registerSchemesAsPrivileged([{
          scheme: 'app',
          privileges: {
            standard: true,
            secure: false,
            supportFetchAPI: true,
            bypassCSP: true
          }
        }]);

        protocol.handle('app', request => {
          const target = path.join(appRoot, new URL(request.url).pathname);
          return net.fetch(target);
        });

        session.defaultSession.setPermissionRequestHandler((webContents, permission, callback) => {
          callback(true);
        });
      `,
      'index.html': `
        <html>
          <head>
            <meta http-equiv="Content-Security-Policy" content="default-src *; script-src * 'unsafe-inline' 'unsafe-eval'">
          </head>
          <body></body>
        </html>
      `
    });

    try {
      const result = await run({
        input: root,
        customScan: [],
        excludeFromScan: []
      });
      const ids = result.issues.map(issue => issue.id);
      const records = result.schemaV1.inventory.records;

      ids.should.include('WINDOW_OPEN_ALLOW_ALL');
      ids.should.include('OPEN_EXTERNAL_UNVALIDATED_URL');
      ids.should.include('OPEN_EXTERNAL_IN_WINDOW_HANDLER_UNVALIDATED');
      ids.should.include('CUSTOM_PROTOCOL_BYPASS_CSP');
      ids.should.include('CUSTOM_PROTOCOL_FILE_PATH_TRAVERSAL_RISK');
      ids.should.include('CUSTOM_PROTOCOL_RISKY_PRIVILEGE_COMBINATION');
      ids.should.include('PERMISSION_HANDLER_ALLOW_ALL');
      ids.should.include('PERMISSION_HANDLER_NO_ORIGIN_CHECK');
      ids.should.include('CSP_UNSAFE_INLINE');
      ids.should.include('CSP_UNSAFE_EVAL');
      ids.should.include('CSP_SCRIPT_SRC_WILDCARD');
      ids.should.include('CSP_WEAK_FOR_RENDERER_XSS');

      records.some(record => record.entity_type === 'navigation_handler' && record.allow_all === true).should.equal(true);
      records.some(record => record.entity_type === 'external_open' && record.visible_url_validation === false).should.equal(true);
      records.some(record => record.entity_type === 'protocol_scheme' && record.privileges.bypassCSP === true).should.equal(true);
      records.some(record => record.entity_type === 'protocol_handler' && record.path_influenced_by_url === true).should.equal(true);
      records.some(record => record.entity_type === 'permission_handler' && record.allow_all === true).should.equal(true);
      records.some(record => record.entity_type === 'csp_policy' && record.meaningfully_reduces_renderer_js_risk === false).should.equal(true);

      ids.filter(id => id === 'WINDOW_OPEN_ALLOW_ALL').length.should.equal(1);
    } finally {
      removeFixtureRoot(root);
    }
  });



  it('honors safe counterexamples and eng-disable compatibility for Phase 7 checks', async function () {
    this.timeout(10000);

    const root = writeFixtureFiles({
      'main.js': `
        const { BrowserWindow, session, shell } = require('electron');

        const win = new BrowserWindow({});
        win.webContents.setWindowOpenHandler(({ url }) => {
          const parsed = new URL(url);
          if (parsed.protocol === 'https:' && ['app.example.com'].includes(parsed.hostname))
            return { action: 'allow' };
          return { action: 'deny' };
        });

        session.defaultSession.setPermissionRequestHandler((webContents, permission, callback, details) => {
          const parsed = new URL(details.requestingUrl);
          if (parsed.origin === 'https://app.example.com' && ['media'].includes(permission))
            callback(true);
          else
            callback(false);
        });

        shell.openExternal(details.url); // eng-disable openExternalUnvalidatedUrl
        shell.openExternal('https://docs.example.com');
      `,
      'index.html': `
        <meta http-equiv="Content-Security-Policy" content="default-src 'self'; script-src 'self'; object-src 'none'">
      `
    });

    try {
      const result = await run({
        input: root,
        customScan: [],
        excludeFromScan: []
      });
      const ids = result.issues.map(issue => issue.id);

      ids.should.not.include('WINDOW_OPEN_ALLOW_ALL');
      ids.should.not.include('NAVIGATION_ALLOW_ALL');
      ids.should.not.include('PERMISSION_HANDLER_ALLOW_ALL');
      ids.should.not.include('PERMISSION_HANDLER_NO_ORIGIN_CHECK');
      ids.should.not.include('OPEN_EXTERNAL_UNVALIDATED_URL');
      ids.should.not.include('CSP_UNSAFE_INLINE');
      ids.should.not.include('CSP_UNSAFE_EVAL');
      ids.should.not.include('CSP_SCRIPT_SRC_WILDCARD');
      ids.should.not.include('CSP_WEAK_FOR_RENDERER_XSS');
    } finally {
      removeFixtureRoot(root);
    }
  });

  it('flags missing permission handlers when remote renderer content is statically visible', async function () {
    this.timeout(10000);

    const root = writeFixtureFiles({
      'main.js': `
        const { BrowserWindow } = require('electron');
        const win = new BrowserWindow({});
        win.loadURL('https://remote.example.test/app');
      `
    });

    try {
      const result = await run({
        input: root,
        customScan: [],
        excludeFromScan: []
      });

      result.issues.map(issue => issue.id).should.include('PERMISSION_HANDLER_MISSING_FOR_REMOTE_CONTENT');
    } finally {
      removeFixtureRoot(root);
    }
  });
});

describe('Phase 8 renderer sink and content-vector hypotheses', () => {
  it('emits renderer sink inventory, content-vector inventory, findings, and shallow hypotheses', async function () {
    this.timeout(10000);

    const root = writeFixtureFiles({
      'renderer.js': `
        export function importUploadedFile(file) {
          const preview = document.querySelector('#preview');
          const metadata = file.name + ':' + file.type;
          preview.innerHTML = metadata;
        }
      `
    });

    try {
      const result = await run({
        input: root,
        customScan: [],
        excludeFromScan: []
      });
      const records = result.schemaV1.inventory.records;
      const hypotheses = result.schemaV1.hypotheses;

      result.issues.map(issue => issue.id).should.include('RENDERER_POTENTIAL_XSS_SINK');
      result.issues.map(issue => issue.id).should.include('RENDERER_SANITIZER_WEAK_OR_UNKNOWN');
      records.some(record => record.entity_type === 'renderer_sink' && record.sink_label === 'dom_inner_html').should.equal(true);
      records.some(record => record.entity_type === 'content_vector' && record.source_label === 'file_upload_import').should.equal(true);

      hypotheses.length.should.equal(1);
      hypotheses[0].source_label.should.equal('file_upload_import');
      hypotheses[0].sink_label.should.equal('dom_inner_html');
      hypotheses[0].candidate_chain.map(step => step.kind).should.deep.equal(['source', 'sink']);
      hypotheses[0].missing_evidence.should.include('source-to-sink trace');
      hypotheses[0].electron_component.should.equal('renderer');
      hypotheses[0].trust_boundary.should.equal('content_to_renderer_script');
      hypotheses[0].affected_window_or_channel.should.equal('unknown_renderer');
    } finally {
      removeFixtureRoot(root);
    }
  });


  it('does not create untrusted content hypotheses for ordinary ES module imports near safe static markup', async function () {
    this.timeout(10000);

    const root = writeFixtureFiles({
      'file_importer/renderer.js': `
        import React from 'react';
        export function renderStaticHeader(element) {
          element.innerHTML = '<strong>Ready</strong>';
        }
      `
    });

    try {
      const result = await run({
        input: root,
        customScan: [],
        excludeFromScan: []
      });
      const ids = result.issues.map(issue => issue.id);
      const records = result.schemaV1.inventory.records;

      ids.should.not.include('RENDERER_SANITIZER_WEAK_OR_UNKNOWN');
      records.some(record => record.entity_type === 'content_vector' && record.source_label === 'file_upload_import').should.equal(false);
      result.schemaV1.hypotheses.length.should.equal(0);
    } finally {
      removeFixtureRoot(root);
    }
  });
});

describe('Phase 9 Electron Team context handoff', () => {
  it('writes hypotheses and context packet counts to output-dir artifacts', async function () {
    this.timeout(10000);

    const root = writeFixtureFiles({
      'renderer.js': `
        function renderPastedComment(comment) {
          document.querySelector('#comment').insertAdjacentHTML('beforeend', comment.html);
        }
      `
    });
    const outputDir = path.join(root, 'out');

    try {
      const result = await run({
        input: root,
        customScan: [],
        excludeFromScan: [],
        outputDir,
        targetId: 'phase-9-handoff'
      });
      const context = parseJson(path.join(outputDir, 'electron-team-context.json'));
      const hypotheses = parseJsonl(path.join(outputDir, 'hypotheses.jsonl'));

      fs.existsSync(path.join(outputDir, 'run.json')).should.equal(true);
      fs.existsSync(path.join(outputDir, 'inventory.json')).should.equal(true);
      fs.existsSync(path.join(outputDir, 'summary.md')).should.equal(true);
      context.packet_type.should.equal('electron_team_context');
      context.target.target_id.should.equal('phase-9-handoff');
      context.artifact_files.hypotheses.should.equal('hypotheses.jsonl');
      context.counts.hypotheses.should.equal(hypotheses.length);
      hypotheses.length.should.equal(result.schemaV1.hypotheses.length);
      hypotheses[0].next_agent_hint.should.contain('renderer sink tracing');
    } finally {
      removeFixtureRoot(root);
    }
  });
});
