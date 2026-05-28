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
