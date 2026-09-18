import type { Investigation } from '../../shared/cyber/investigation-types';
import { HypothesisService, type ChallengerAssessment } from './hypothesis-service';

export interface ChallengerReviewResult {
  investigationId: string;
  generatedAt: number;
  reviews: ChallengerAssessment[];
}

export class ChallengerAgent {
  constructor(private readonly hypothesisService = new HypothesisService()) {}

  reviewInvestigation(investigation: Investigation): ChallengerReviewResult {
    return {
      investigationId: investigation.id,
      generatedAt: Date.now(),
      reviews: investigation.hypotheses.map((item) => this.hypothesisService.challenge(investigation, item.id)),
    };
  }
}
