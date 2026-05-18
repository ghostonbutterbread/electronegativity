import { parseModule as esprima_parse } from 'esprima';
import * as babelParser from "@babel/parser";
import * as typescriptEstreeParser from '@typescript-eslint/typescript-estree';
import { load as cheerio_load } from 'cheerio';

import { extension } from '../util';
import { sourceTypes, sourceExtensions } from './types';
import { classifyFile } from './file_classification';

import { EsprimaAst, BabelAst, ESLintAst, TreeSettings, Scope } from '../finder/ast';

export class Parser {
  constructor(babelFirst, typescriptBabelFirst, classificationOptions = {}) {
    this.esLintESTreeAst = new ESLintAst(new TreeSettings());
    this.esLintBabelTreeAst = new ESLintAst(new TreeSettings({propertyName: 'ObjectProperty', stringLiteral: 'StringLiteral'}));
    this.babelAst = new BabelAst(new TreeSettings({propertyName: 'ObjectProperty', stringLiteral: 'StringLiteral'}));
    this.esprimaAst = new EsprimaAst(new TreeSettings());

    this.babelFirst = babelFirst;
    this.typescriptBabelFirst = typescriptBabelFirst;
    this.classificationOptions = classificationOptions;
    this.babelPlugins = [
      "jsx",
      "objectRestSpread",
      "classProperties",
      "optionalCatchBinding",
      "asyncGenerators",
      "decorators-legacy",
      "flow",
      "dynamicImport",
      "optionalChaining",
      "nullishCoalescingOperator",
      "classPrivateProperties",
      "classPrivateMethods",
      "importMeta",
      "topLevelAwait",
      "logicalAssignment",
      "numericSeparator",
      "estree",
    ]

    this.tsPlugins = [
      "jsx",
      "objectRestSpread",
      "classProperties",
      "optionalCatchBinding",
      "asyncGenerators",
      "decorators-legacy",
      "typescript",
      "dynamicImport",
      "optionalChaining",
      "nullishCoalescingOperator",
      "classPrivateProperties",
      "classPrivateMethods",
      "importMeta",
      "topLevelAwait",
      "logicalAssignment",
      "numericSeparator",
    ]

    this.fileClassifications = new Map();
  }

  addPlugin(plugin) {
    this.tsPlugins.push(plugin)
    this.babelPlugins.push(plugin)
  }

  parseEsprima(content) {
    let data = esprima_parse(content, { loc: true, tolerant: true, jsx: true });
    data.astParser = this.esprimaAst;
    data.Scope = new Scope(data);
    data.parserName = 'esprima';
    return data;
  }

  parseBabel(content) {
    let data = babelParser.parse(content, {
      sourceType: "module",
      plugins: this.babelPlugins,
      ecmaFeatures: {
          modules: true
      }
    }).program;

    data.astParser = this.esLintESTreeAst;
    data.Scope = new Scope(data);
    data.parserName = 'babel';
    return data;
  }

  parseTypeScript(content) {
    let data = babelParser.parse(content, {
      sourceType: "module",
      plugins: this.tsPlugins
    });

    data.astParser = this.esLintBabelTreeAst;
    data.Scope = {}; // new Scope(data);
    data.Scope.resolveVarValue = (astNode) => astNode.arguments[0];
    data.Scope.updateFunctionScope = () => {};
    data.parserName = 'babel-typescript';
    return data;
  }

  parseTypescriptEstree(content) {
    let data = typescriptEstreeParser.parse(content, {
      loc: true,
      range: true,
      tokens: true,
      errorOnUnknownASTType: true,
      useJSXTextNode: true,
      ecmaFeatures: {
        jsx: true,
        modules: true
      }
    });

    data.astParser = this.esLintESTreeAst;
    data.Scope = {}; //new Scope(data);
    data.Scope.resolveVarValue = (astNode) => astNode.arguments[0];
    data.Scope.updateFunctionScope = () => {};
    data.parserName = 'typescript-estree';
    return data;
  }

  getFileClassification(filename) {
    return this.fileClassifications.get(filename);
  }

  parse(filename, content) {
    const ext = extension(filename);

    const sourceType = sourceExtensions[ext];
    content = content.toString();
    let data = null;
    let classification = classifyFile(filename, content, Object.assign({}, this.classificationOptions, {
      parserStatus: sourceType === undefined ? 'unsupported' : 'unparsed',
      sourceType
    }));
    this.fileClassifications.set(filename, classification);

    try {
      switch (sourceType) {
        case sourceTypes.JAVASCRIPT:
          // replace shebang (https://en.wikipedia.org/wiki/Shebang_(Unix)) with spaces to keep offsets intact
          content = content.replace(/(^#!.*)/, function(m) { return Array(m.length + 1).join(' '); });

          if(ext === 'ts' || ext === 'tsx') {
            try {
              data = this.typescriptBabelFirst ? this.parseTypeScript(content) : this.parseTypescriptEstree(content);
            } catch (error1) {
              try {
                data = this.typescriptBabelFirst ? this.parseTypescriptEstree(content) : this.parseTypeScript(content);
              } catch (error2) {
                throw this.typescriptBabelFirst ? error1 : error2; // prefer babel as it contains line number
              }
            }
            break;
          }

          try {
            data = this.babelFirst ? this.parseBabel(content) : this.parseEsprima(content);
          } catch (error) {
            data = this.babelFirst ? this.parseEsprima(content) : this.parseBabel(content);
          }
          break;
        case sourceTypes.HTML:
          data = cheerio_load(content, { xmlMode: true, withStartIndices: true, lowerCaseTags: true, lowerCaseAttributeNames: true });
          data.parserName = 'cheerio';
          break;
        case sourceTypes.JSON:
          data = {json: JSON.parse(content), text: content, parserName: 'json'};
          break;
        default:
          break;
      }

      const warnings = data ? data.errors : undefined;
      classification = classifyFile(filename, content, Object.assign({}, this.classificationOptions, {
        parserStatus: data === null ? 'unsupported' : (warnings && warnings.length > 0 ? 'tolerant_errors' : 'ok'),
        parser: data ? data.parserName : null,
        sourceType
      }));
      if (data)
        data.fileClassification = classification;
      this.fileClassifications.set(filename, classification);

      return [sourceType, data, content, warnings];
    } catch (error) {
      classification = classifyFile(filename, content, Object.assign({}, this.classificationOptions, {
        parserStatus: 'error',
        sourceType,
        parseError: error.message
      }));
      this.fileClassifications.set(filename, classification);
      throw error;
    }
  }
}
