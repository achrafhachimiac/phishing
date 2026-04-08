import React, { useState } from 'react';
import { Login } from './components/Login';
import { DomainAnalysis } from './components/DomainAnalysis';
import { EmailAnalysis } from './components/EmailAnalysis';
import { Terminal, Shield, LogOut } from 'lucide-react';

export default function App() {
  const [isLoggedIn, setIsLoggedIn] = useState(false);
  const [activeTab, setActiveTab] = useState<'domain' | 'email'>('domain');

  if (!isLoggedIn) {
    return <Login onLogin={() => setIsLoggedIn(true)} />;
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
            onClick={() => setIsLoggedIn(false)}
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
        </div>

        <main className="animate-in fade-in slide-in-from-bottom-4 duration-500">
          {activeTab === 'domain' ? <DomainAnalysis /> : <EmailAnalysis />}
        </main>
        
        <footer className="mt-12 text-center text-xs opacity-50 border-t border-cyber-red-dim pt-4">
          <p>WARNING: USE FOR AUTHORIZED INVESTIGATIONS ONLY.</p>
          <p>ALL QUERIES ARE LOGGED.</p>
        </footer>
      </div>
    </div>
  );
}

