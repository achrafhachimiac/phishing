import React from 'react';

type SignalTone = 'safe' | 'warning' | 'neutral' | 'danger';

function joinClasses(...values: Array<string | false | null | undefined>) {
  return values.filter(Boolean).join(' ');
}

function getSignalContentMetadata(children: React.ReactNode) {
  const normalizedText = typeof children === 'string'
    ? children.trim().toLowerCase()
    : typeof children === 'number'
      ? String(children)
      : null;

  const isAnimatedProgressWord = normalizedText === 'running' || normalizedText === 'parsing';
  const isCriticalAlert = normalizedText === 'critical' || normalizedText === '100';

  return {
    isAnimatedProgressWord,
    isCriticalAlert,
    normalizedText,
  };
}

function renderSignalChildren(children: React.ReactNode) {
  const { isAnimatedProgressWord, normalizedText } = getSignalContentMetadata(children);

  if (!isAnimatedProgressWord || !normalizedText) {
    return children;
  }

  return (
    <span
      className="signal-progress-word"
      style={{ ['--signal-progress-ch' as '--signal-progress-ch']: `${normalizedText.length}ch` }}
    >
      {children}
    </span>
  );
}

export function SignalBadge({
  tone,
  children,
  blink = false,
  className,
}: {
  tone: SignalTone;
  children: React.ReactNode;
  blink?: boolean;
  className?: string;
}) {
  const { isCriticalAlert } = getSignalContentMetadata(children);

  return (
    <span
      className={joinClasses(
        'signal-badge',
        tone === 'safe' && 'signal-badge-safe',
        tone === 'warning' && 'signal-badge-warning',
        tone === 'neutral' && 'signal-badge-neutral',
        tone === 'danger' && 'signal-badge-danger',
        blink && tone === 'warning' && 'signal-blink',
        blink && tone === 'danger' && 'signal-blink-danger',
        isCriticalAlert && 'signal-critical-glow',
        className,
      )}
    >
      {renderSignalChildren(children)}
    </span>
  );
}

export function SignalPanel({
  tone,
  children,
  blink = false,
  className,
}: {
  tone: SignalTone;
  children: React.ReactNode;
  blink?: boolean;
  className?: string;
}) {
  const { isCriticalAlert } = getSignalContentMetadata(children);

  return (
    <div
      className={joinClasses(
        'signal-panel',
        tone === 'safe' && 'signal-panel-safe',
        tone === 'warning' && 'signal-panel-warning',
        tone === 'neutral' && 'signal-panel-neutral',
        tone === 'danger' && 'signal-panel-danger',
        blink && tone === 'warning' && 'signal-blink-soft',
        blink && tone === 'danger' && 'signal-blink-danger-soft',
        isCriticalAlert && 'signal-critical-glow',
        className,
      )}
    >
      {renderSignalChildren(children)}
    </div>
  );
}

export function SignalText({
  tone,
  children,
  blink = false,
  className,
}: {
  tone: SignalTone;
  children: React.ReactNode;
  blink?: boolean;
  className?: string;
}) {
  const { isCriticalAlert } = getSignalContentMetadata(children);

  return (
    <span
      className={joinClasses(
        tone === 'safe' && 'signal-text-safe',
        tone === 'warning' && 'signal-text-warning',
        tone === 'neutral' && 'signal-text-neutral',
        tone === 'danger' && 'signal-text-danger',
        blink && tone === 'warning' && 'signal-blink',
        blink && tone === 'danger' && 'signal-blink-danger',
        isCriticalAlert && 'signal-critical-glow',
        className,
      )}
    >
      {renderSignalChildren(children)}
    </span>
  );
}

export function toneFromBinaryFlag(flag: boolean): SignalTone {
  return flag ? 'warning' : 'safe';
}

export function toneFromFileVerdict(verdict: string): SignalTone {
  return verdict === 'clean' ? 'safe' : 'warning';
}

export function toneFromRiskLevel(level: string | null | undefined): SignalTone {
  const normalizedLevel = level?.toUpperCase();
  if (normalizedLevel === 'LOW') {
    return 'safe';
  }

  if (normalizedLevel === 'CRITICAL') {
    return 'danger';
  }

  return normalizedLevel ? 'warning' : 'neutral';
}

export function toneFromRiskScore(score: number): SignalTone {
  if (score >= 100) {
    return 'danger';
  }

  return score >= 25 ? 'warning' : 'safe';
}

export function toneFromScannerStatus(status: string | null | undefined): SignalTone {
  const normalizedStatus = status?.toLowerCase();
  if (!normalizedStatus) {
    return 'neutral';
  }

  if (['clean', 'not_listed', 'pass', 'present', 'completed', 'ready', 'low'].includes(normalizedStatus)) {
    return 'safe';
  }

  if (['pending', 'unknown', 'not_configured'].includes(normalizedStatus)) {
    return 'neutral';
  }

  if (['critical'].includes(normalizedStatus)) {
    return 'danger';
  }

  if (['malicious', 'match', 'listed', 'submitted', 'suspicious', 'fail', 'softfail', 'high', 'running', 'queued', 'stopped', 'failed', 'unavailable', 'absent', 'parsing'].includes(normalizedStatus)) {
    return 'warning';
  }

  return 'neutral';
}

export function isBlinkingSignal(tone: SignalTone, shouldBlink?: boolean) {
  return (tone === 'warning' || tone === 'danger') && Boolean(shouldBlink);
}