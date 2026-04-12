import { credentialsRules } from "./credentials.js";
import { networkRules } from "./network.js";
import { dataPolicyRules } from "./data-policy.js";
import { dangerousNodesRules } from "./dangerous-nodes.js";
import { expressionInjectionRules } from "./expression-injection.js";
import { hygieneRules } from "./hygiene.js";
import { supplyChainRules } from "./supply-chain.js";
import { dataFlowRules } from "./data-flow.js";
import { loopFlowRules } from "./loop-flow.js";
import { reliabilityRules } from "./reliability.js";
import { observabilityRules } from "./observability.js";
import { maintainabilityRules } from "./maintainability.js";
import { dataQualityRules } from "./data-quality.js";
import { performanceRules } from "./performance.js";
import type { RuleRunner } from "../types.js";

export const ALL_RULES: RuleRunner[] = [
  ...credentialsRules,
  ...networkRules,
  ...dataPolicyRules,
  ...dangerousNodesRules,
  ...expressionInjectionRules,
  ...hygieneRules,
  ...supplyChainRules,
  ...dataFlowRules,
  ...loopFlowRules,
  ...reliabilityRules,
  ...observabilityRules,
  ...maintainabilityRules,
  ...dataQualityRules,
  ...performanceRules,
];

export {
  credentialsRules,
  networkRules,
  dataPolicyRules,
  dangerousNodesRules,
  expressionInjectionRules,
  hygieneRules,
  supplyChainRules,
  dataFlowRules,
  loopFlowRules,
  reliabilityRules,
  observabilityRules,
  maintainabilityRules,
  dataQualityRules,
  performanceRules,
};
