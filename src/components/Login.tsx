import React, { useState } from 'react';
import { Terminal, Lock, ShieldAlert } from 'lucide-react';

interface LoginProps {
  onLogin: () => void;
}

export function Login({ onLogin }: LoginProps) {
  const [password, setPassword] = useState('');
  const [error, setError] = useState(false);

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    // Simple hardcoded password for the prototype
    if (password === 'Fr&dCl@ssic') {
      onLogin();
    } else {
      setError(true);
      setPassword('');
      setTimeout(() => setError(false), 2000);
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-cyber-bg relative overflow-hidden crt">
      <div className="scanline"></div>
      
      <div className="cli-border p-8 max-w-md w-full bg-black/80 backdrop-blur-sm relative z-10">
        <div className="flex flex-col items-center mb-8">
          <ShieldAlert size={48} className="text-cyber-red mb-4 animate-pulse" />
          <h1 className="text-2xl font-bold tracking-widest text-center uppercase">
            Phish_Hunter_OSINT v2.4
          </h1>
          <p className="text-xs mt-2 opacity-70">UNAUTHORIZED ACCESS STRICTLY PROHIBITED</p>
        </div>

        <form onSubmit={handleSubmit} className="space-y-6">
          <div>
            <label className="block text-xs mb-2 uppercase tracking-wider">
              <Terminal size={12} className="inline mr-2" />
              Enter Access Key
            </label>
            <div className="relative">
              <Lock size={16} className="absolute left-3 top-1/2 -translate-y-1/2 opacity-50" />
              <input
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                className="cli-input w-full py-2 pl-10 pr-4"
                placeholder="••••••••"
                autoFocus
              />
            </div>
            {error && (
              <p className="text-xs mt-2 animate-bounce">
                [!] ACCESS DENIED. INVALID CREDENTIALS.
              </p>
            )}
          </div>

          <button type="submit" className="cli-button w-full py-3 font-bold tracking-widest">
            INITIALIZE SYSTEM
          </button>
        </form>
        
        <div className="mt-8 text-[10px] opacity-50 text-center space-y-1">
          <p>SYSTEM: ONLINE</p>
          <p>CONNECTION: SECURE</p>
          <p>IP: [REDACTED]</p>
        </div>
      </div>
    </div>
  );
}
