import { RendererInventoryCollector } from './renderer_collector';
import { PreloadIpcCollector, isPreloadIpcAuditCheckName } from './preload_ipc_collector';
import { StaticTrustCollector, isStaticTrustAuditCheckName } from './static_trust_collector';

module.exports.RendererInventoryCollector = RendererInventoryCollector;
module.exports.PreloadIpcCollector = PreloadIpcCollector;
module.exports.StaticTrustCollector = StaticTrustCollector;
module.exports.isPreloadIpcAuditCheckName = isPreloadIpcAuditCheckName;
module.exports.isStaticTrustAuditCheckName = isStaticTrustAuditCheckName;
