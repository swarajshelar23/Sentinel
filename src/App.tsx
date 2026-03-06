import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import { useState, useEffect } from 'react';
import Navbar from './components/Navbar';
import Landing from './pages/Landing';
import Auth from './pages/Auth';
import Dashboard from './pages/Dashboard';
import History from './pages/History';
import ScanResult from './pages/ScanResult';
import Analytics from './pages/Analytics';
import Admin from './pages/Admin';

export default function App() {
  const [user, setUser] = useState<any>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const storedUser = localStorage.getItem('user');
    const token = localStorage.getItem('token');
    if (storedUser && token) {
      setUser(JSON.parse(storedUser));
    }
    setLoading(false);
  }, []);

  const logout = () => {
    localStorage.removeItem('user');
    localStorage.removeItem('token');
    setUser(null);
  };

  if (loading) return <div className="min-h-screen bg-[#E4E3E0] flex items-center justify-center font-mono">INITIALIZING_SYSTEM...</div>;

  return (
    <Router>
      <div className="min-h-screen bg-[#E4E3E0] text-[#141414] font-sans selection:bg-[#141414] selection:text-[#E4E3E0]">
        <Navbar user={user} onLogout={logout} />
        <main className="container mx-auto px-4 py-8">
          <Routes>
            <Route path="/" element={<Landing />} />
            <Route path="/auth" element={!user ? <Auth onLogin={setUser} /> : <Navigate to="/dashboard" />} />
            <Route path="/dashboard" element={user ? <Dashboard /> : <Navigate to="/auth" />} />
            <Route path="/history" element={user ? <History /> : <Navigate to="/auth" />} />
            <Route path="/scan/:id" element={user ? <ScanResult /> : <Navigate to="/auth" />} />
            <Route path="/analytics" element={user ? <Analytics /> : <Navigate to="/auth" />} />
            <Route path="/admin" element={user?.role === 'admin' ? <Admin /> : <Navigate to="/dashboard" />} />
          </Routes>
        </main>
      </div>
    </Router>
  );
}
