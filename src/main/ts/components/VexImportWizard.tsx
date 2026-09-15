import React, { useMemo, useState } from 'react';
import { DetectedRisk, fetchDetectedRisks } from '../api/scaDetectedRisks';
import { BranchInfo } from '../api/projectBranches';
import { applyStatusChanges, StatusChangeResult } from '../api/scaChangeStatus';
import { assessImport, AssessmentResult } from '../vex/assessImport';
import { parseVex, VexParseError, VexParseResult } from '../vex/parseVex';
import { Disclaimer } from './shared/Disclaimer';
import { StepIntro } from './wizard/StepIntro';
import { StepSelectFile } from './wizard/StepSelectFile';
import { StepAssessment } from './wizard/StepAssessment';
import { StepApprove } from './wizard/StepApprove';
import { StepResult } from './wizard/StepResult';

interface Component {
  key: string;
  name: string;
  qualifier?: string;
}

interface BranchLike {
  name: string;
  isMain?: boolean;
}

export interface VexImportWizardProps {
  component: Component;
  branchLike?: BranchLike;
}

export type WizardStep = 1 | 2 | 3 | 4 | 5;

export function VexImportWizard({ component, branchLike }: Readonly<VexImportWizardProps>) {
  const [step, setStep] = useState<WizardStep>(1);

  const [selectedBranch, setSelectedBranch] = useState<BranchInfo | null>(null);
  const [vexFile, setVexFile] = useState<File | null>(null);
  const [parsedVex, setParsedVex] = useState<VexParseResult | null>(null);
  const [parseError, setParseError] = useState<string | null>(null);

  const [detectedRisks, setDetectedRisks] = useState<DetectedRisk[] | null>(null);
  const [detectedRisksLoading, setDetectedRisksLoading] = useState(false);
  const [detectedRisksError, setDetectedRisksError] = useState<string | null>(null);

  const [userComment, setUserComment] = useState('');

  const [applyLoading, setApplyLoading] = useState(false);
  const [applyError, setApplyError] = useState<string | null>(null);
  const [applyResults, setApplyResults] = useState<StatusChangeResult[] | null>(null);

  const assessment: AssessmentResult | null = useMemo(() => {
    if (!parsedVex || !detectedRisks) return null;
    return assessImport(parsedVex, detectedRisks);
  }, [parsedVex, detectedRisks]);

  function handleFileSelected(file: File, rawText: string) {
    setVexFile(file);
    try {
      setParsedVex(parseVex(rawText));
      setParseError(null);
    } catch (e) {
      setParsedVex(null);
      setParseError(e instanceof VexParseError ? e.message : String(e));
    }
  }

  async function goToAssessment() {
    if (!selectedBranch) return;
    setStep(3);
    setDetectedRisksLoading(true);
    setDetectedRisksError(null);
    try {
      const risks = await fetchDetectedRisks(component.key, selectedBranch.name);
      setDetectedRisks(risks);
    } catch (e) {
      setDetectedRisksError(e instanceof Error ? e.message : String(e));
    } finally {
      setDetectedRisksLoading(false);
    }
  }

  async function handleApply() {
    if (!assessment) return;
    setApplyLoading(true);
    setApplyError(null);
    try {
      const trimmedUserComment = userComment.trim();
      const changes = assessment.importable.map((item) => ({
        issueReleaseKey: item.issueReleaseKey,
        transitionKey: item.transitionKey,
        comment: trimmedUserComment ? `${item.comment} — ${trimmedUserComment}` : item.comment,
      }));
      const results = await applyStatusChanges(changes);
      setApplyResults(results);
      setStep(5);
    } catch (e) {
      setApplyError(e instanceof Error ? e.message : String(e));
    } finally {
      setApplyLoading(false);
    }
  }

  function handleStartOver() {
    setStep(1);
    setVexFile(null);
    setParsedVex(null);
    setParseError(null);
    setDetectedRisks(null);
    setDetectedRisksError(null);
    setUserComment('');
    setApplyResults(null);
    setApplyError(null);
  }

  if (component.qualifier && component.qualifier !== 'TRK') {
    return (
      <div style={{ padding: '32px', fontFamily: 'sans-serif' }}>
        <Disclaimer />
        <p style={{ color: '#666' }}>VEX Import is only available at the project level.</p>
      </div>
    );
  }

  return (
    <div style={{ padding: '32px', fontFamily: 'sans-serif', maxWidth: '900px' }}>
      <Disclaimer />
      <h1 style={{ fontSize: '20px', fontWeight: 700, marginBottom: '24px', color: '#1a1a1a' }}>VEX Import</h1>

      {step === 1 && <StepIntro onNext={() => setStep(2)} />}

      {step === 2 && (
        <StepSelectFile
          projectKey={component.key}
          branchLikeName={branchLike?.name}
          vexFile={vexFile}
          selectedBranch={selectedBranch}
          parseError={parseError}
          canProceed={Boolean(vexFile && parsedVex && selectedBranch)}
          onFileSelected={handleFileSelected}
          onBranchSelected={setSelectedBranch}
          onBack={() => setStep(1)}
          onNext={goToAssessment}
        />
      )}

      {step === 3 && (
        <StepAssessment
          loading={detectedRisksLoading}
          error={detectedRisksError}
          assessment={assessment}
          onBack={() => setStep(2)}
          onNext={() => setStep(4)}
        />
      )}

      {step === 4 && assessment && (
        <StepApprove
          assessment={assessment}
          userComment={userComment}
          onUserCommentChange={setUserComment}
          applyLoading={applyLoading}
          applyError={applyError}
          onBack={() => setStep(3)}
          onApply={handleApply}
        />
      )}

      {step === 5 && assessment && applyResults && (
        <StepResult assessment={assessment} results={applyResults} onStartOver={handleStartOver} />
      )}
    </div>
  );
}
