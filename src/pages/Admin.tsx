import { useState, useEffect } from 'react';
import axios from 'axios';
import { motion } from 'motion/react';
import { 
  Shield, Users, Activity, Terminal, Database, 
  AlertTriangle, CheckCircle, Clock, Search, Filter
} from 'lucide-react';

export default function Admin() {
  const [logs, setLogs] = useState<any[]>([]);
  const [scans, setScans] = useState<any[]>([]);
  const [health, setHealth] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const [tab, setTab] = useState<'scans' | 'logs' | 'system'>('scans');

  useEffect(() => {
    const fetchData = async () => {
      try {
        const token = localStorage.getItem('token');
        const [logsRes, scansRes, healthRes] = await Promise.all([
          axios.get('/api/admin/logs', { headers: { Authorization: `Bearer ${token}` } }),
          axios.get('/api/admin/scans', { headers: { Authorization: `Bearer ${token}` } }),
          axios.get('/api/admin/health', { headers: { Authorization: `Bearer ${token}` } })
        ]);
        setLogs(logsRes.data);
        setScans(scansRes.data);
        setHealth(healthRes.data);
      } catch (err) {
        console.error('Failed to fetch admin data');
      } finally {
        setLoading(false);
      }
    };
    fetchData();
  }, []);

  if (loading) return <div className="font-mono text-center py-20">INITIALIZING_ADMIN_INTERFACE...</div>;

  return (
    <div className="max-w-7xl mx-auto space-y-8">
      <div className="flex justify-between items-end">
        <div>
          <h1 className="text-4xl font-black tracking-tighter uppercase">Sentinel_Command_Center</h1>
          <p className="font-mono text-xs opacity-50">ADMINISTRATIVE_OVERWATCH_&_SYSTEM_CONTROL</p>
        </div>
        <div className="flex gap-2">
          <div className="flex items-center gap-2 px-4 py-2 bg-green-50 border border-green-600 text-green-700 font-mono text-[10px] font-bold">
            <Activity className="w-3 h-3" /> SYSTEM_HEALTH: {health?.status.toUpperCase()}
          </div>
        </div>
      </div>

      {/* Navigation Tabs */}
      <div className="flex gap-4 border-b border-[#141414]/10">
        {[
          { id: 'scans', label: 'GLOBAL_SCANS', icon: Shield },
          { id: 'logs', label: 'AUDIT_LOGS', icon: Terminal },
          { id: 'system', label: 'SYSTEM_MONITOR', icon: Database }
        ].map((t) => (
          <button
            key={t.id}
            onClick={() => setTab(t.id as any)}
            className={`flex items-center gap-2 px-6 py-4 font-mono text-xs font-bold transition-all ${
              tab === t.id ? 'border-b-2 border-[#141414] opacity-100' : 'opacity-30 hover:opacity-50'
            }`}
          >
            <t.icon className="w-4 h-4" /> {t.label}
          </button>
        ))}
      </div>

      {/* Content Area */}
      <motion.div 
        key={tab}
        initial={{ opacity: 0, y: 10 }}
        animate={{ opacity: 1, y: 0 }}
        className="bg-white border border-[#141414]"
      >
        {tab === 'scans' && (
          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse">
              <thead>
                <tr className="bg-[#141414] text-[#E4E3E0] font-mono text-[10px] uppercase">
                  <th className="p-4">Timestamp</th>
                  <th className="p-4">User</th>
                  <th className="p-4">Filename</th>
                  <th className="p-4">Classification</th>
                  <th className="p-4">Score</th>
                  <th className="p-4">Action</th>
                </tr>
              </thead>
              <tbody className="text-sm">
                {scans.map((scan) => (
                  <tr key={scan.id} className="border-b border-[#141414]/5 hover:bg-gray-50">
                    <td className="p-4 font-mono text-[10px]">{new Date(scan.created_at).toLocaleString()}</td>
                    <td className="p-4 font-bold">{scan.username}</td>
                    <td className="p-4 truncate max-w-[200px]">{scan.filename}</td>
                    <td className="p-4">
                      <span className={`px-2 py-1 text-[10px] font-bold uppercase ${
                        scan.classification === 'Safe' ? 'bg-green-100 text-green-700' : 
                        scan.classification === 'Suspicious' ? 'bg-yellow-100 text-yellow-700' : 
                        'bg-red-100 text-red-700'
                      }`}>
                        {scan.classification}
                      </span>
                    </td>
                    <td className="p-4 font-mono font-bold">{scan.threat_score}</td>
                    <td className="p-4">
                      <button className="text-[10px] font-bold underline uppercase">View_Report</button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        {tab === 'logs' && (
          <div className="p-4 space-y-2 font-mono text-[10px]">
            {logs.map((log) => (
              <div key={log.id} className="flex gap-4 p-2 border-b border-[#141414]/5 hover:bg-gray-50">
                <span className="opacity-30">[{new Date(log.created_at).toLocaleTimeString()}]</span>
                <span className={`font-bold w-32 ${
                  log.event_type.includes('FAILED') ? 'text-red-600' : 
                  log.event_type.includes('SUCCESS') ? 'text-green-600' : 'text-blue-600'
                }`}>
                  {log.event_type}
                </span>
                <span className="w-24 opacity-50">{log.username || 'SYSTEM'}</span>
                <span className="flex-1">{log.message}</span>
                <span className="opacity-30">{log.ip_address}</span>
              </div>
            ))}
          </div>
        )}

        {tab === 'system' && health && (
          <div className="p-8 grid md:grid-cols-2 gap-12">
            <div className="space-y-8">
              <h3 className="font-mono font-bold text-sm uppercase opacity-50">Infrastructure_Metrics</h3>
              <div className="grid grid-cols-2 gap-4">
                <div className="p-4 bg-gray-50 border border-[#141414]/5">
                  <p className="font-mono text-[10px] uppercase opacity-50 mb-1">Uptime</p>
                  <p className="text-xl font-bold">{(health.uptime / 3600).toFixed(2)} HOURS</p>
                </div>
                <div className="p-4 bg-gray-50 border border-[#141414]/5">
                  <p className="font-mono text-[10px] uppercase opacity-50 mb-1">DB_Size</p>
                  <p className="text-xl font-bold">{(health.db_size / 1024 / 1024).toFixed(2)} MB</p>
                </div>
                <div className="p-4 bg-gray-50 border border-[#141414]/5">
                  <p className="font-mono text-[10px] uppercase opacity-50 mb-1">Memory_Usage</p>
                  <p className="text-xl font-bold">{(health.memory.rss / 1024 / 1024).toFixed(1)} MB</p>
                </div>
                <div className="p-4 bg-gray-50 border border-[#141414]/5">
                  <p className="font-mono text-[10px] uppercase opacity-50 mb-1">Active_Jobs</p>
                  <p className="text-xl font-bold">{health.active_jobs.count}</p>
                </div>
              </div>
            </div>
            <div className="space-y-8">
              <h3 className="font-mono font-bold text-sm uppercase opacity-50">Security_Status</h3>
              <div className="space-y-4">
                <div className="flex items-center justify-between p-4 border border-green-600 bg-green-50">
                  <div className="flex items-center gap-3">
                    <CheckCircle className="w-5 h-5 text-green-600" />
                    <span className="font-bold text-sm">Rate Limiting Active</span>
                  </div>
                  <span className="font-mono text-[10px] opacity-50">100 REQ/MIN</span>
                </div>
                <div className="flex items-center justify-between p-4 border border-green-600 bg-green-50">
                  <div className="flex items-center gap-3">
                    <CheckCircle className="w-5 h-5 text-green-600" />
                    <span className="font-bold text-sm">Audit Logging Enabled</span>
                  </div>
                  <span className="font-mono text-[10px] opacity-50">FULL_TRACE</span>
                </div>
                <div className="flex items-center justify-between p-4 border border-yellow-600 bg-yellow-50">
                  <div className="flex items-center gap-3">
                    <AlertTriangle className="w-5 h-5 text-yellow-600" />
                    <span className="font-bold text-sm">Sandbox Mode</span>
                  </div>
                  <span className="font-mono text-[10px] opacity-50">RESTRICTED</span>
                </div>
              </div>
            </div>
          </div>
        )}
      </motion.div>
    </div>
  );
}
