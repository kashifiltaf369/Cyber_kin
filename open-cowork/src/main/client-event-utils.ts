import type { ClientEvent } from '../renderer/types';

export function eventRequiresSessionManager(event: ClientEvent): boolean {
  switch (event.type) {
    case 'session.start':
    case 'session.continue':
    case 'session.stop':
    case 'session.delete':
    case 'session.batchDelete':
    case 'session.list':
    case 'session.getMessages':
    case 'session.getTraceSteps':
    case 'session.compact':
    case 'session.getContextUsage':
    case 'permission.response':
    case 'investigation.create':
    case 'investigation.list':
    case 'investigation.get':
    case 'investigation.open':
    case 'investigation.resume':
    case 'investigation.archive':
    case 'investigation.plan':
    case 'investigation.replan':
    case 'investigation.getLatestReplanRecommendation':
    case 'investigation.execute':
    case 'investigation.pauseTask':
    case 'investigation.resumeTask':
    case 'investigation.reprioritizeTask':
    case 'investigation.createTask':
    case 'investigation.applyHumanInterruption':
    case 'investigation.cancelTask':
    case 'investigation.redirectTask':
    case 'investigation.exportReport':
    case 'investigation.getReport':
      return true;
    default:
      return false;
  }
}
