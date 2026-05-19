import { sourceTypes } from '../../../parser/types';
import { severity, confidence } from '../../attributes';
import { buildCheckProperties, defaultBehaviorForSetting, issueClassificationForDefaultBehavior } from '../../../util/electron_context';

export default class SandboxJSCheck {
  constructor() {
    this.id = "SANDBOX_JS_CHECK";
    this.description = __("SANDBOX_JS_CHECK");
    this.type = sourceTypes.JAVASCRIPT;
    this.shortenedURL = "https://git.io/JeuM2";
  }

  match(astNode, astHelper, scope, defaults, electronVersion, versionContext){
    if (astNode.type !== 'NewExpression') return null;
    if (astNode.callee.name !== 'BrowserWindow' && astNode.callee.name !== 'BrowserView') return null;

    let wasFound = false;
    let loc = [];
    if (astNode.arguments.length > 0) {

      var target = scope.resolveVarValue(astNode);

      const found_nodes = astHelper.findNodeByType(target,
        astHelper.PropertyName,
        astHelper.PropertyDepth,
        false,
        node => (node.key.value === 'sandbox' || node.key.name === 'sandbox'));

      for (const node of found_nodes) {
        wasFound = true;
        if (node.value.value === true) {
          continue;
        }
        loc.push(this.explicitIssue(node.key.loc.start.line, node.key.loc.start.column, versionContext));
      }
    }

    if (wasFound) {
      return loc;
    } else { // default is false
      return [this.missingSettingIssue(astNode.loc.start.line, astNode.loc.start.column, versionContext)];
    }
  }

  explicitIssue(line, column, versionContext) {
    return {
      line,
      column,
      id: this.id,
      description: this.description,
      shortenedURL: this.shortenedURL,
      severity: severity.MEDIUM,
      confidence: confidence.FIRM,
      manualReview: false,
      properties: buildCheckProperties('sandbox', versionContext)
    };
  }

  missingSettingIssue(line, column, versionContext) {
    const defaultBehavior = defaultBehaviorForSetting('sandbox', versionContext);
    const issueClassification = issueClassificationForDefaultBehavior('sandbox', defaultBehavior);

    return {
      line,
      column,
      id: this.id,
      description: this.description,
      shortenedURL: this.shortenedURL,
      severity: defaultBehavior.known ? (defaultBehavior.value ? severity.INFORMATIONAL : severity.MEDIUM) : severity.LOW,
      confidence: defaultBehavior.known ? confidence.FIRM : confidence.TENTATIVE,
      manualReview: !defaultBehavior.known,
      properties: buildCheckProperties('sandbox', versionContext, { issueClassification })
    };
  }
}
