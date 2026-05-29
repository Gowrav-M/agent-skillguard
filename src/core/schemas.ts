import { z } from "zod";

export const severitySchema = z.enum(["info", "low", "medium", "high", "critical"]);
export const capabilitySchema = z.enum([
  "network",
  "shell",
  "filesystem-read",
  "filesystem-write",
  "git-read",
  "git-write",
  "browser-automation",
  "mcp-tool-mutation",
  "package-install",
  "secret-access"
]);

export const skillManifestSchema = z.object({
  name: z.string().min(1),
  description: z.string().default(""),
  version: z.string().optional(),
  source: z.string().optional(),
  declaredCapabilities: z.array(capabilitySchema).default([])
});

export const skillFileSchema = z.object({
  path: z.string().min(1),
  size: z.number().int().nonnegative(),
  sha256: z.string().regex(/^[a-f0-9]{64}$/),
  kind: z.enum(["markdown", "script", "manifest", "json", "binary", "other"])
});

export const skillScriptSchema = z.object({
  path: z.string().min(1),
  interpreter: z.string(),
  capabilities: z.array(capabilitySchema)
});

export const skillFindingSchema = z.object({
  id: z.string().min(1),
  severity: severitySchema,
  category: z.string().min(1),
  title: z.string().min(1),
  description: z.string().min(1),
  recommendation: z.string().min(1),
  target: z.string().min(1),
  evidence: z.array(z.string()).default([])
});

export const skillBomEntrySchema = z.object({
  root: z.string().min(1),
  manifest: skillManifestSchema,
  files: z.array(skillFileSchema),
  scripts: z.array(skillScriptSchema),
  observedCapabilities: z.array(capabilitySchema).default([]),
  capabilities: z.array(capabilitySchema)
});

export const skillBomSchema = z.object({
  generatedAt: z.string().datetime(),
  skills: z.array(skillBomEntrySchema)
});

export const skillLockSchema = z.object({
  schemaVersion: z.literal(1),
  generatedAt: z.string().datetime(),
  root: z.string().min(1),
  files: z.array(skillFileSchema),
  capabilities: z.array(capabilitySchema)
});

export const skillGuardReportSchema = z.object({
  generatedAt: z.string().datetime(),
  summary: z.object({
    skills: z.number().int().nonnegative(),
    files: z.number().int().nonnegative(),
    findings: z.number().int().nonnegative(),
    riskScore: z.number().int().min(0).max(100)
  }),
  bom: skillBomSchema,
  findings: z.array(skillFindingSchema)
});

export const skillGuardPolicySchema = z.object({
  schemaVersion: z.literal(1),
  blockOnSeverity: severitySchema.default("critical"),
  deniedCapabilities: z.array(capabilitySchema).default(["secret-access", "mcp-tool-mutation"]),
  requireLockfile: z.boolean().default(false),
  requireCleanScan: z.boolean().default(false),
  allowInstallScripts: z.boolean().default(false)
});

export const admissionReasonSchema = z.object({
  severity: severitySchema,
  code: z.string().min(1),
  message: z.string().min(1),
  target: z.string().min(1)
});

export const skillAdmissionDecisionSchema = z.object({
  generatedAt: z.string().datetime(),
  decision: z.enum(["allow", "review", "block"]),
  summary: z.object({
    skills: z.number().int().nonnegative(),
    findings: z.number().int().nonnegative(),
    riskScore: z.number().int().min(0).max(100)
  }),
  policy: skillGuardPolicySchema,
  reasons: z.array(admissionReasonSchema),
  report: skillGuardReportSchema
});

export const skillUpdateReviewSchema = z.object({
  generatedAt: z.string().datetime(),
  decision: z.enum(["allow", "review", "block"]),
  summary: z.object({
    previousRiskScore: z.number().int().min(0).max(100),
    candidateRiskScore: z.number().int().min(0).max(100),
    addedCapabilities: z.array(capabilitySchema),
    removedCapabilities: z.array(capabilitySchema),
    addedFiles: z.array(z.string()),
    removedFiles: z.array(z.string()),
    modifiedFiles: z.array(z.string()),
    newFindings: z.number().int().nonnegative()
  }),
  reasons: z.array(admissionReasonSchema),
  previous: skillGuardReportSchema,
  candidate: skillGuardReportSchema
});

export const skillProvenanceSchema = z.object({
  schemaVersion: z.literal(1),
  generatedAt: z.string().datetime(),
  skillName: z.string().min(1),
  sourceUri: z.string().min(1),
  sourceHost: z.string().min(1),
  sourceOwner: z.string().optional(),
  sourceRepo: z.string().optional(),
  sourceRef: z.string().optional(),
  sourceCommit: z.string().optional(),
  publisher: z.string().optional(),
  skillDigest: z.string().regex(/^sha256:[a-f0-9]{64}$/)
});

export const skillTrustPolicySchema = z.object({
  schemaVersion: z.literal(1),
  allowedHosts: z.array(z.string().min(1)).default(["github.com"]),
  allowedPublishers: z.array(z.string().min(1)).default([]),
  requirePinnedCommit: z.boolean().default(true),
  denyMutableRefs: z.boolean().default(true)
});

export const skillTrustDecisionSchema = z.object({
  generatedAt: z.string().datetime(),
  decision: z.enum(["allow", "review", "block"]),
  provenance: skillProvenanceSchema,
  policy: skillTrustPolicySchema,
  reasons: z.array(admissionReasonSchema)
});

export const skillCapabilityContractSchema = z.object({
  skillName: z.string().min(1),
  declaredCapabilities: z.array(capabilitySchema),
  observedCapabilities: z.array(capabilitySchema),
  undeclaredCapabilities: z.array(capabilitySchema),
  unusedDeclarations: z.array(capabilitySchema)
});

export const skillContractDecisionSchema = z.object({
  generatedAt: z.string().datetime(),
  decision: z.enum(["allow", "review", "block"]),
  summary: z.object({
    skills: z.number().int().nonnegative(),
    violations: z.number().int().nonnegative(),
    undeclaredCapabilities: z.number().int().nonnegative()
  }),
  contracts: z.array(skillCapabilityContractSchema),
  reasons: z.array(admissionReasonSchema),
  report: skillGuardReportSchema
});

export const skillIntentReviewSchema = z.object({
  generatedAt: z.string().datetime(),
  decision: z.enum(["allow", "review", "block"]),
  summary: z.object({
    skills: z.number().int().nonnegative(),
    signals: z.number().int().nonnegative(),
    criticalSignals: z.number().int().nonnegative(),
    highSignals: z.number().int().nonnegative(),
    riskScore: z.number().int().min(0).max(100)
  }),
  signals: z.array(skillFindingSchema),
  report: skillGuardReportSchema
});

export const skillPassportSchema = z.object({
  schemaVersion: z.literal(1),
  generatedAt: z.string().datetime(),
  skillName: z.string().min(1),
  decision: z.enum(["allow", "review", "block"]),
  source: skillProvenanceSchema,
  digests: z.object({
    skillDigest: z.string().regex(/^sha256:[a-f0-9]{64}$/),
    lockDigest: z.string().regex(/^sha256:[a-f0-9]{64}$/),
    bundleDigest: z.string().regex(/^sha256:[a-f0-9]{64}$/).optional()
  }),
  summary: z.object({
    riskScore: z.number().int().min(0).max(100),
    findings: z.number().int().nonnegative(),
    intentSignals: z.number().int().nonnegative().default(0),
    capabilityViolations: z.number().int().nonnegative(),
    admissionReasons: z.number().int().nonnegative(),
    trustReasons: z.number().int().nonnegative(),
    decisionReasons: z.number().int().nonnegative()
  }),
  artifacts: z.array(z.string()),
  embedded: z.object({
    scan: skillGuardReportSchema,
    trust: skillTrustDecisionSchema,
    contract: skillContractDecisionSchema,
    admission: skillAdmissionDecisionSchema,
    intent: skillIntentReviewSchema.optional(),
    lock: skillLockSchema
  })
});

export const skillPassportVerificationSchema = z.object({
  generatedAt: z.string().datetime(),
  valid: z.boolean(),
  passportDecision: z.enum(["allow", "review", "block"]),
  checked: z.object({
    schema: z.boolean(),
    lockDigest: z.boolean(),
    skillDigest: z.boolean().optional(),
    bundleDigest: z.boolean().optional(),
    decisionConsistency: z.boolean()
  }),
  reasons: z.array(admissionReasonSchema),
  passport: skillPassportSchema
});

export const skillRiskBaselineEntrySchema = z.object({
  id: z.string().min(1),
  source: z.enum(["scan", "intent"]),
  severity: severitySchema,
  category: z.string().min(1),
  target: z.string().min(1),
  title: z.string().min(1),
  acceptedAt: z.string().datetime(),
  reason: z.string().min(1),
  expiresAt: z.string().optional()
});

export const skillRiskBaselineSchema = z.object({
  schemaVersion: z.literal(1),
  generatedAt: z.string().datetime(),
  scope: z.string().min(1),
  reason: z.string().min(1),
  accepted: z.array(skillRiskBaselineEntrySchema)
});

export const skillRiskTriageSchema = z.object({
  generatedAt: z.string().datetime(),
  decision: z.enum(["allow", "review", "block"]),
  summary: z.object({
    accepted: z.number().int().nonnegative(),
    unresolved: z.number().int().nonnegative(),
    unresolvedFindings: z.number().int().nonnegative(),
    unresolvedIntentSignals: z.number().int().nonnegative(),
    riskScore: z.number().int().min(0).max(100)
  }),
  baseline: skillRiskBaselineSchema,
  report: skillGuardReportSchema,
  intent: skillIntentReviewSchema,
  unresolvedFindings: z.array(skillFindingSchema),
  unresolvedIntentSignals: z.array(skillFindingSchema)
});

export type Severity = z.infer<typeof severitySchema>;
export type SkillCapability = z.infer<typeof capabilitySchema>;
export type SkillManifest = z.infer<typeof skillManifestSchema>;
export type SkillFile = z.infer<typeof skillFileSchema>;
export type SkillScript = z.infer<typeof skillScriptSchema>;
export type SkillFinding = z.infer<typeof skillFindingSchema>;
export type SkillBomEntry = z.infer<typeof skillBomEntrySchema>;
export type SkillBom = z.infer<typeof skillBomSchema>;
export type SkillLock = z.infer<typeof skillLockSchema>;
export type SkillGuardReport = z.infer<typeof skillGuardReportSchema>;
export type SkillGuardPolicy = z.infer<typeof skillGuardPolicySchema>;
export type AdmissionReason = z.infer<typeof admissionReasonSchema>;
export type SkillAdmissionDecision = z.infer<typeof skillAdmissionDecisionSchema>;
export type SkillUpdateReview = z.infer<typeof skillUpdateReviewSchema>;
export type SkillProvenance = z.infer<typeof skillProvenanceSchema>;
export type SkillTrustPolicy = z.infer<typeof skillTrustPolicySchema>;
export type SkillTrustDecision = z.infer<typeof skillTrustDecisionSchema>;
export type SkillCapabilityContract = z.infer<typeof skillCapabilityContractSchema>;
export type SkillContractDecision = z.infer<typeof skillContractDecisionSchema>;
export type SkillIntentReview = z.infer<typeof skillIntentReviewSchema>;
export type SkillPassport = z.infer<typeof skillPassportSchema>;
export type SkillPassportVerification = z.infer<typeof skillPassportVerificationSchema>;
export type SkillRiskBaselineEntry = z.infer<typeof skillRiskBaselineEntrySchema>;
export type SkillRiskBaseline = z.infer<typeof skillRiskBaselineSchema>;
export type SkillRiskTriage = z.infer<typeof skillRiskTriageSchema>;
