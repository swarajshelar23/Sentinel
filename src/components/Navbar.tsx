import { Link, useNavigate } from 'react-router-dom';
import { Shield, History, LayoutDashboard, LogOut, Terminal } from 'lucide-react';

export default function Navbar({ user, onLogout }: { user: any, onLogout: () => void }) {
  const navigate = useNavigate();

  return (
    <nav className="border-b border-[#141414] bg-[#E4E3E0] sticky top-0 z-50">
      <div className="container mx-auto px-4 h-16 flex items-center justify-between">
        <Link to="/" className="flex items-center gap-2 group">
          <Shield className="w-6 h-6 group-hover:rotate-12 transition-transform" />
          <span className="font-mono font-bold tracking-tighter text-lg">Sentinel Prime</span>
        </Link>

        <div className="flex items-center gap-6">
          {user ? (
            <>
              <Link to="/dashboard" className="flex items-center gap-1.5 text-sm font-medium hover:underline underline-offset-4">
                <LayoutDashboard className="w-4 h-4" />
                DASHBOARD
              </Link>
              <Link to="/analytics" className="flex items-center gap-1.5 text-sm font-medium hover:underline underline-offset-4">
                <Shield className="w-4 h-4" />
                ANALYTICS
              </Link>
              <Link to="/history" className="flex items-center gap-1.5 text-sm font-medium hover:underline underline-offset-4">
                <History className="w-4 h-4" />
                HISTORY
              </Link>
              {user.role === 'admin' && (
                <Link to="/admin" className="flex items-center gap-1.5 text-sm font-medium hover:underline underline-offset-4 text-red-600">
                  <Terminal className="w-4 h-4" />
                  ADMIN
                </Link>
              )}
              <button 
                onClick={() => { onLogout(); navigate('/'); }}
                className="flex items-center gap-1.5 text-sm font-medium hover:underline underline-offset-4 cursor-pointer"
              >
                <LogOut className="w-4 h-4" />
                LOGOUT
              </button>
              <div className="flex items-center gap-2 pl-4 border-l border-[#141414]/20">
                <Terminal className="w-4 h-4 opacity-50" />
                <span className="font-mono text-xs opacity-70 uppercase">{user.username}</span>
              </div>
            </>
          ) : (
            <Link to="/auth" className="text-sm font-bold bg-[#141414] text-[#E4E3E0] px-4 py-2 hover:opacity-90 transition-opacity">
              ACCESS_SYSTEM
            </Link>
          )}
        </div>
      </div>
    </nav>
  );
}
