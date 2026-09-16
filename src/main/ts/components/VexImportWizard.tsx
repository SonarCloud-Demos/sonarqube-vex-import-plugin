import React, { useMemo, useState } from 'react';
import { fetchDetectedRisks } from '../api/scaDetectedRisks';
import { BranchInfo } from '../api/projectBranches';
import { applyStatusChanges, StatusChangeResult } from '../api/scaChangeStatus';
import { fetchIssueReleaseChangelog } from '../api/scaChangelog';
import { assessImport, AssessmentResult, PlanItem } from '../vex/assessImport';
import { parseVex, VexParseError, VexParseResult } from '../vex/parseVex';
import { Disclaimer } from './shared/Disclaimer';
import { StepIntro } from './wizard/StepIntro';
import { StepSelectFile } from './wizard/StepSelectFile';
import { StepAssessment } from './wizard/StepAssessment';
import { StepConflicts, ConflictResolution } from './wizard/StepConflicts';
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

export type WizardStep = 'intro' | 'selectFile' | 'assessment' | 'conflicts' | 'approve' | 'result';

export function VexImportWizard({ component, branchLike }: Readonly<VexImportWizardProps>) {
  const [step, setStep] = useState<WizardStep>('intro');

  const [selectedBranch, setSelectedBranch] = useState<BranchInfo | null>(null);
  const [vexFile, setVexFile] = useState<File | null>(null);
  const [parsedVex, setParsedVex] = useState<VexParseResult | null>(null);
  const [parseError, setParseError] = useState<string | null>(null);

  const [assessment, setAssessment] = useState<AssessmentResult | null>(null);
  const [assessmentLoading, setAssessmentLoading] = useState(false);
  const [assessmentError, setAssessmentError] = useState<string | null>(null);

  const [conflictResolutions, setConflictResolutions] = useState<Map<string, ConflictResolution>>(new Map());

  const [userComment, setUserComment] = useState('');

  const [applyLoading, setApplyLoading] = useState(false);
  const [applyError, setApplyError] = useState<string | null>(null);
  const [applyResults, setApplyResults] = useState<StatusChangeResult[] | null>(null);

  const finalImportable: PlanItem[] = useMemo(() => {
    if (!assessment) return [];
    const resolvedConflicts = assessment.conflicts
      .filter((c) => (conflictResolutions.get(c.item.issueReleaseKey) ?? 'keep') === 'apply')
      .map((c) => c.item);
    return [...assessment.importable, ...resolvedConflicts];
  }, [assessment, conflictResolutions]);

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
    if (!selectedBranch || !parsedVex) return;
    setStep('assessment');
    setAssessmentLoading(true);
    setAssessmentError(null);
    setAssessment(null);
    setConflictResolutions(new Map());
    try {
      const risks = await fetchDetectedRisks(component.key, selectedBranch.name);
      const result = await assessImport(parsedVex, risks, fetchIssueReleaseChangelog);
      setAssessment(result);
    } catch (e) {
      setAssessmentError(e instanceof Error ? e.message : String(e));
    } finally {
      setAssessmentLoading(false);
    }
  }

  function goFromAssessment() {
    setStep(assessment && assessment.conflicts.length > 0 ? 'conflicts' : 'approve');
  }

  function goBackFromApprove() {
    setStep(assessment && assessment.conflicts.length > 0 ? 'conflicts' : 'assessment');
  }

  async function handleApply() {
    setApplyLoading(true);
    setApplyError(null);
    try {
      const trimmedUserComment = userComment.trim();
      const changes = finalImportable.map((item) => ({
        issueReleaseKey: item.issueReleaseKey,
        transitionKey: item.transitionKey,
        comment: trimmedUserComment ? `${item.comment} - ${trimmedUserComment}` : item.comment,
      }));
      const results = await applyStatusChanges(changes);
      setApplyResults(results);
      setStep('result');
    } catch (e) {
      setApplyError(e instanceof Error ? e.message : String(e));
    } finally {
      setApplyLoading(false);
    }
  }

  function handleStartOver() {
    setStep('intro');
    setVexFile(null);
    setParsedVex(null);
    setParseError(null);
    setAssessment(null);
    setAssessmentError(null);
    setConflictResolutions(new Map());
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

      {step === 'intro' && <StepIntro onNext={() => setStep('selectFile')} />}

      {step === 'selectFile' && (
        <StepSelectFile
          projectKey={component.key}
          branchLikeName={branchLike?.name}
          vexFile={vexFile}
          selectedBranch={selectedBranch}
          parseError={parseError}
          canProceed={Boolean(vexFile && parsedVex && selectedBranch)}
          onFileSelected={handleFileSelected}
          onBranchSelected={setSelectedBranch}
          onBack={() => setStep('intro')}
          onNext={goToAssessment}
        />
      )}

      {step === 'assessment' && (
        <StepAssessment
          loading={assessmentLoading}
          error={assessmentError}
          assessment={assessment}
          onBack={() => setStep('selectFile')}
          onNext={goFromAssessment}
        />
      )}

      {step === 'conflicts' && assessment && (
        <StepConflicts
          conflicts={assessment.conflicts}
          resolutions={conflictResolutions}
          onResolutionsChange={setConflictResolutions}
          onBack={() => setStep('assessment')}
          onNext={() => setStep('approve')}
        />
      )}

      {step === 'approve' && (
        <StepApprove
          finalImportable={finalImportable}
          userComment={userComment}
          onUserCommentChange={setUserComment}
          applyLoading={applyLoading}
          applyError={applyError}
          onBack={goBackFromApprove}
          onApply={handleApply}
        />
      )}

      {step === 'result' && applyResults && (
        <StepResult finalImportable={finalImportable} results={applyResults} onStartOver={handleStartOver} />
      )}
    </div>
  );
}
