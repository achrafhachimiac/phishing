import React, { useEffect, useState } from 'react';
import { Login } from './components/Login';
import { DomainAnalysis } from './components/DomainAnalysis';
import { EmailAnalysis } from './components/EmailAnalysis';
import { BrowserSandbox } from './components/BrowserSandbox';
import { FileAnalysis } from './components/FileAnalysis';
import { ThePhish } from './components/ThePhish';
import { Terminal, Shield, LogOut } from 'lucide-react';

export default function App() {
  const [authState, setAuthState] = useState<'checking' | 'authenticated' | 'unauthenticated'>('checking');
  const [activeTab, setActiveTab] = useState<'domain' | 'email' | 'sandbox' | 'files' | 'thephish'>('domain');

  useEffect(() => {
    let cancelled = false;

    const loadSession = async () => {
      try {
        const response = await fetch('/api/auth/session');
        const payload = (await response.json()) as { authenticated?: boolean };
        if (!cancelled) {
          setAuthState(payload.authenticated ? 'authenticated' : 'unauthenticated');
        }
      } catch {
        if (!cancelled) {
          setAuthState('unauthenticated');
        }
      }
    };

    void loadSession();

    return () => {
      cancelled = true;
    };
  }, []);

  const handleLogout = async () => {
    try {
      await fetch('/api/auth/logout', { method: 'POST' });
    } finally {
      setAuthState('unauthenticated');
    }
  };

  if (authState === 'checking') {
    return (
      <div className="min-h-screen flex items-center justify-center bg-cyber-bg text-cyber-red font-mono crt">
        <div className="scanline"></div>
        <div className="cli-border p-8 bg-black/80 relative z-10 text-center">
          <Shield className="mx-auto mb-4 animate-pulse" size={36} />
          <div className="tracking-widest uppercase">Restoring Secure Session...</div>
        </div>
      </div>
    );
  }

  if (authState !== 'authenticated') {
    return <Login onLogin={() => setAuthState('authenticated')} />;
  }

  return (
    <div className="min-h-screen bg-cyber-bg text-cyber-red font-mono crt relative overflow-x-hidden">
      <div className="scanline"></div>
      
      <div className="max-w-6xl mx-auto p-4 md:p-8 relative z-10">
        <header className="flex flex-col md:flex-row justify-between items-center mb-8 border-b border-cyber-red pb-4">
          <div className="flex items-center mb-4 md:mb-0">
            <Shield className="mr-3 animate-pulse" size={32} />
            <div>
              <h1 className="text-2xl font-bold tracking-widest uppercase">Phish_Hunter_OSINT</h1>
              <p className="text-xs opacity-70">v2.4 // SECURE CONNECTION ESTABLISHED</p>
            </div>
          </div>
          
          <button 
            onClick={() => {
              void handleLogout();
            }}
            className="cli-button px-4 py-2 text-xs flex items-center"
          >
            <LogOut size={14} className="mr-2" /> TERMINATE SESSION
          </button>
        </header>

        <div className="flex space-x-4 mb-8">
          <button
            onClick={() => setActiveTab('domain')}
            className={`cli-button px-6 py-3 flex-1 md:flex-none ${activeTab === 'domain' ? 'bg-cyber-red text-cyber-bg shadow-[0_0_15px_rgba(255,42,42,0.5)]' : ''}`}
          >
            [1] DOMAIN ANALYSIS
          </button>
          <button
            onClick={() => setActiveTab('email')}
            className={`cli-button px-6 py-3 flex-1 md:flex-none ${activeTab === 'email' ? 'bg-cyber-red text-cyber-bg shadow-[0_0_15px_rgba(255,42,42,0.5)]' : ''}`}
          >
            [2] FULL EMAIL ANALYSIS
          </button>
          <button
            onClick={() => setActiveTab('sandbox')}
            className={`cli-button px-6 py-3 flex-1 md:flex-none ${activeTab === 'sandbox' ? 'bg-cyber-red text-cyber-bg shadow-[0_0_15px_rgba(255,42,42,0.5)]' : ''}`}
          >
            [3] URL SANDBOX
          </button>
          <button
            onClick={() => setActiveTab('files')}
            className={`cli-button px-6 py-3 flex-1 md:flex-none ${activeTab === 'files' ? 'bg-cyber-red text-cyber-bg shadow-[0_0_15px_rgba(255,42,42,0.5)]' : ''}`}
          >
            [4] FILE ANALYSIS
          </button>
          <button
            onClick={() => setActiveTab('thephish')}
            className={`cli-button px-6 py-3 flex-1 md:flex-none ${activeTab === 'thephish' ? 'bg-cyber-red text-cyber-bg shadow-[0_0_15px_rgba(255,42,42,0.5)]' : ''}`}
          >
            [5] THEPHISH
          </button>
        </div>

        <main className="animate-in fade-in slide-in-from-bottom-4 duration-500">
          {activeTab === 'domain' ? <DomainAnalysis /> : null}
          {activeTab === 'email' ? <EmailAnalysis /> : null}
          {activeTab === 'sandbox' ? <BrowserSandbox /> : null}
          {activeTab === 'files' ? <FileAnalysis /> : null}
          {activeTab === 'thephish' ? <ThePhish /> : null}
        </main>
        
        <footer className="mt-12 text-center text-xs opacity-50 border-t border-cyber-red-dim pt-4">
          <p>WARNING: USE FOR AUTHORIZED INVESTIGATIONS ONLY.</p>
          <p>ALL QUERIES ARE LOGGED.</p>
        </footer>
      </div>
    </div>
  );
}

