import { credentialsRules } from "./credentials.js";
import { networkRules } from "./network.js";
import { dataPolicyRules } from "./data-policy.js";
import { dangerousNodesRules } from "./dangerous-nodes.js";
import { expressionInjectionRules } from "./expression-injection.js";
import { hygieneRules } from "./hygiene.js";
import type { RuleRunner } from "../types.js";

export const ALL_RULES: RuleRunner[] = [
  ...credentialsRules,
  ...networkRules,
  ...dataPolicyRules,
  ...dangerousNodesRules,
  ...expressionInjectionRules,
  ...hygieneRules,
];

export { credentialsRules, networkRules, dataPolicyRules, dangerousNodesRules, expressionInjectionRules, hygieneRules };
