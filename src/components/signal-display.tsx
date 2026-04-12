import React from 'react';

type SignalTone = 'safe' | 'warning' | 'neutral';

function joinClasses(...values: Array<string | false | null | undefined>) {
  return values.filter(Boolean).join(' ');
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
  return (
    <span
      className={joinClasses(
        'signal-badge',
        tone === 'safe' && 'signal-badge-safe',
        tone === 'warning' && 'signal-badge-warning',
        tone === 'neutral' && 'signal-badge-neutral',
        blink && tone === 'warning' && 'signal-blink',
        className,
      )}
    >
      {children}
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
  return (
    <div
      className={joinClasses(
        'signal-panel',
        tone === 'safe' && 'signal-panel-safe',
        tone === 'warning' && 'signal-panel-warning',
        tone === 'neutral' && 'signal-panel-neutral',
        blink && tone === 'warning' && 'signal-blink-soft',
        className,
      )}
    >
      {children}
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
  return (
    <span
      className={joinClasses(
        tone === 'safe' && 'signal-text-safe',
        tone === 'warning' && 'signal-text-warning',
        tone === 'neutral' && 'signal-text-neutral',
        blink && tone === 'warning' && 'signal-blink',
        className,
      )}
    >
      {children}
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
  return normalizedLevel === 'LOW' ? 'safe' : normalizedLevel ? 'warning' : 'neutral';
}

export function toneFromRiskScore(score: number): SignalTone {
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

  if (['malicious', 'match', 'listed', 'submitted', 'suspicious', 'fail', 'softfail', 'high', 'critical', 'running', 'queued', 'stopped', 'failed', 'unavailable', 'absent'].includes(normalizedStatus)) {
    return 'warning';
  }

  return 'neutral';
}

export function isBlinkingSignal(tone: SignalTone, shouldBlink?: boolean) {
  return tone === 'warning' && Boolean(shouldBlink);
}