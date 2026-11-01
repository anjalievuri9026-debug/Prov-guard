import React, { useState } from 'react';
import { AuthProvider, useAuth } from './context/AuthContext';
import { Sidebar, NavPage } from './components/Sidebar';
import { Header } from './components/Header';
import { LoginPage } from './pages/LoginPage';
import { DashboardPage } from './pages/DashboardPage';
import { VaultPage } from './pages/VaultPage';
import { UploadPage } from './pages/UploadPage';
import { EvidenceDetailPage } from './pages/EvidenceDetailPage';
import { CustodyPage } from './pages/CustodyPage';
import { AuditPage } from './pages/AuditPage';
import { ReportsPage } from './pages/ReportsPage';
import { UsersPage } from './pages/UsersPage';
import { RefreshCw } from 'lucide-react';

const MainShell: React.FC = () => {
  const { user, isLoading } = useAuth();
  const [currentPage, setCurrentPage] = useState<NavPage>('dashboard');
  const [activeEvidenceId, setActiveEvidenceId] = useState<string | null>(null);
  const [mobileSidebarOpen, setMobileSidebarOpen] = useState<boolean>(false);
  const [refreshCounter, setRefreshCounter] = useState<number>(0);

  const handleNavigate = (page: NavPage, evidenceId?: string) => {
    setCurrentPage(page);
    if (evidenceId) {
      setActiveEvidenceId(evidenceId);
    }
  };

  if (isLoading) {
    return (
      <div className="min-h-screen bg-[#060911] text-slate-400 flex flex-col items-center justify-center">
        <RefreshCw className="w-8 h-8 animate-spin text-cyan-400 mb-3" />
        <p className="text-xs font-mono tracking-widest text-slate-400 uppercase">
          INITIALIZING DEIV CRYPTOGRAPHIC VAULT...
        </p>
      </div>
    );
  }

  if (!user) {
    return <LoginPage />;
  }

  const getPageTitle = (page: NavPage): { title: string; subtitle: string } => {
    switch (page) {
      case 'dashboard':
        return {
          title: 'Forensic Security Command Center',
          subtitle: 'Cryptographic SHA-256 integrity metrics, live custody stream & audit status',
        };
      case 'vault':
        return {
          title: 'Digital Evidence Vault',
          subtitle: 'Private restricted repository with real-time byte stream verification',
        };
      case 'upload':
        return {
          title: 'Acquire New Evidence',
          subtitle: 'Ingest digital files into secure private vault with SHA-256 seal',
        };
      case 'evidence-detail':
        return {
          title: `Evidence Inspection Dossier`,
          subtitle: activeEvidenceId ? `Inspecting ${activeEvidenceId} cryptographic verification history` : '',
        };
      case 'custody':
        return {
          title: 'Master Chain of Custody',
          subtitle: 'Chronological chronological audit trail of all custody transfers and access',
        };
      case 'audit':
        return {
          title: 'Cryptographic Tamper-Evident Audit Chain',
          subtitle: 'SHA-256 linked node block verification from Genesis anchor',
        };
      case 'reports':
        return {
          title: 'Forensic PDF Report Center',
          subtitle: 'Official Evidence Certificates with cryptographic proof seals',
        };
      case 'users':
        return {
          title: 'Administrator Access Control',
          subtitle: 'Role-Based Access Control (RBAC) and operator credential provisioning',
        };
      default:
        return { title: 'DEIV Console', subtitle: 'Digital Evidence Integrity Vault' };
    }
  };

  const { title, subtitle } = getPageTitle(currentPage);

  return (
    <div className="min-h-screen bg-[#060911] text-slate-100 flex">
      {/* Sidebar Navigation */}
      <Sidebar
        currentPage={currentPage}
        onNavigate={(p) => handleNavigate(p)}
        mobileOpen={mobileSidebarOpen}
        onCloseMobile={() => setMobileSidebarOpen(false)}
      />

      {/* Main Content Area */}
      <div className="flex-1 lg:pl-72 flex flex-col min-h-screen overflow-x-hidden">
        <Header
          onToggleMobile={() => setMobileSidebarOpen(!mobileSidebarOpen)}
          onQuickUpload={() => handleNavigate('upload')}
          title={title}
          subtitle={subtitle}
          onRefresh={() => setRefreshCounter((prev) => prev + 1)}
        />

        <main className="flex-1 p-4 lg:p-8 max-w-7xl w-full mx-auto">
          {currentPage === 'dashboard' && <DashboardPage key={refreshCounter} onNavigate={handleNavigate} />}
          {currentPage === 'vault' && <VaultPage key={refreshCounter} onNavigate={handleNavigate} />}
          {currentPage === 'upload' && <UploadPage onNavigate={handleNavigate} />}
          {currentPage === 'evidence-detail' && (
            <EvidenceDetailPage
              key={`${activeEvidenceId}-${refreshCounter}`}
              evidenceId={activeEvidenceId || ''}
              onNavigate={handleNavigate}
            />
          )}
          {currentPage === 'custody' && <CustodyPage key={refreshCounter} onNavigate={handleNavigate} />}
          {currentPage === 'audit' && <AuditPage key={refreshCounter} onNavigate={handleNavigate} />}
          {currentPage === 'reports' && <ReportsPage key={refreshCounter} onNavigate={handleNavigate} />}
          {currentPage === 'users' && <UsersPage key={refreshCounter} />}
        </main>
      </div>
    </div>
  );
};

export default function App() {
  return (
    <AuthProvider>
      <MainShell />
    </AuthProvider>
  );
}
