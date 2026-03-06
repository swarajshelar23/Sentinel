import React, { useState, useEffect, useCallback } from 'react';
import axios from 'axios';
import { motion } from 'motion/react';
import { Upload, FileText, AlertTriangle, ShieldCheck, Activity, Search } from 'lucide-react';
import { useNavigate } from 'react-router-dom';
import {
  Chart as ChartJS,
  ArcElement,
  Tooltip,
  Legend,
  CategoryScale,
  LinearScale,
  BarElement,
} from 'chart.js';
import { Doughnut, Bar } from 'react-chartjs-2';

ChartJS.register(ArcElement, Tooltip, Legend, CategoryScale, LinearScale, BarElement);

export default function Dashboard() {
  const [file, setFile] = useState<File | null>(null);
  const [scanning, setScanning] = useState(false);
  const [stats, setStats] = useState<any>(null);
  const navigate = useNavigate();

  const fetchStats = useCallback(async () => {
    try {
      const token = localStorage.getItem('token');
      const { data } = await axios.get('/api/stats', {
        headers: { Authorization: `Bearer ${token}` }
      });
      setStats(data);
    } catch (err) {
      console.error('Failed to fetch stats');
    }
  }, []);

  useEffect(() => {
    fetchStats();
  }, [fetchStats]);

  const handleUpload = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!file) return;

    setScanning(true);
    const formData = new FormData();
    formData.append('file', file);

    try {
      const token = localStorage.getItem('token');
      const { data } = await axios.post('/api/scan', formData, {
        headers: { 
          Authorization: `Bearer ${token}`,
          'Content-Type': 'multipart/form-data'
        }
      });
      navigate(`/scan/${data.id}`, { state: { scanData: data } });
    } catch (err) {
      alert('Scan failed. Please try again.');
    } finally {
      setScanning(false);
    }
  };

  const doughnutData = {
    labels: ['Safe', 'Suspicious', 'Malware', 'High Risk'],
    datasets: [{
      data: stats ? [stats.safe, stats.suspicious, stats.malware, stats.high_risk] : [0, 0, 0, 0],
      backgroundColor: ['#10b981', '#f59e0b', '#ef4444', '#7f1d1d'],
      borderWidth: 0,
    }]
  };

  return (
    <div className="space-y-8">
      <div className="grid md:grid-cols-3 gap-6">
        <motion.div 
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          className="md:col-span-2 border border-[#141414] p-8 bg-white"
        >
          <div className="flex items-center gap-2 mb-6">
            <Upload className="w-6 h-6" />
            <h2 className="font-mono font-bold text-xl">FILE_UPLOAD_GATEWAY</h2>
          </div>

          <form onSubmit={handleUpload} className="space-y-6">
            <div 
              className={`border-2 border-dashed border-[#141414]/20 p-12 text-center hover:border-[#141414] transition-colors cursor-pointer relative ${file ? 'bg-green-50' : ''}`}
              onDragOver={(e) => e.preventDefault()}
              onDrop={(e) => {
                e.preventDefault();
                if (e.dataTransfer.files[0]) setFile(e.dataTransfer.files[0]);
              }}
            >
              <input 
                type="file" 
                onChange={(e) => e.target.files && setFile(e.target.files[0])}
                className="absolute inset-0 opacity-0 cursor-pointer"
              />
              <Search className="w-12 h-12 mx-auto mb-4 opacity-20" />
              {file ? (
                <div>
                  <p className="font-bold text-lg">{file.name}</p>
                  <p className="font-mono text-xs opacity-50">{(file.size / 1024).toFixed(2)} KB</p>
                </div>
              ) : (
                <>
                  <p className="font-bold text-lg">DROP_FILE_OR_CLICK_TO_BROWSE</p>
                  <p className="font-mono text-xs opacity-50 mt-2">MAX_SIZE: 50MB | SUPPORTED: ALL_TYPES</p>
                </>
              )}
            </div>

            <button 
              type="submit"
              disabled={!file || scanning}
              className="w-full bg-[#141414] text-[#E4E3E0] py-4 font-bold flex items-center justify-center gap-2 hover:opacity-90 disabled:opacity-50 transition-opacity"
            >
              {scanning ? (
                <>
                  <Activity className="w-5 h-5 animate-spin" />
                  ANALYZING_THREAT_VECTORS...
                </>
              ) : (
                <>
                  <ShieldCheck className="w-5 h-5" />
                  INITIATE_SCAN
                </>
              )}
            </button>
          </form>
        </motion.div>

        <motion.div 
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.1 }}
          className="border border-[#141414] p-8 bg-white"
        >
          <h3 className="font-mono font-bold text-sm mb-6 uppercase opacity-50">Global_Threat_Distribution</h3>
          <div className="aspect-square">
            <Doughnut 
              data={doughnutData} 
              options={{ 
                plugins: { legend: { position: 'bottom', labels: { font: { family: 'monospace', size: 10 } } } },
                cutout: '70%'
              }} 
            />
          </div>
          <div className="mt-8 space-y-4">
            <div className="flex justify-between items-center border-b border-[#141414]/10 pb-2">
              <span className="font-mono text-xs">TOTAL_SCANS</span>
              <span className="font-bold">{stats?.total || 0}</span>
            </div>
            <div className="flex justify-between items-center border-b border-[#141414]/10 pb-2">
              <span className="font-mono text-xs">MALICIOUS_DETECTED</span>
              <span className="font-bold text-red-600">{(stats?.malware || 0) + (stats?.high_risk || 0)}</span>
            </div>
          </div>
        </motion.div>
      </div>

      <div className="grid md:grid-cols-4 gap-4">
        {[
          { label: 'SYSTEM_STATUS', value: 'OPERATIONAL', color: 'text-green-600' },
          { label: 'SCAN_ENGINE', value: 'v3.0.0', color: 'text-[#141414]' },
          { label: 'DB_RECORDS', value: stats?.total || 0, color: 'text-[#141414]' },
          { label: 'ACTIVE_ALERTS', value: stats?.high_risk || 0, color: 'text-red-600' }
        ].map((item, i) => (
          <div key={i} className="border border-[#141414] p-4 bg-white">
            <p className="font-mono text-[10px] uppercase opacity-50 mb-1">{item.label}</p>
            <p className={`font-bold ${item.color}`}>{item.value}</p>
          </div>
        ))}
      </div>
    </div>
  );
}
