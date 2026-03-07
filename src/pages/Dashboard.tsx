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
  const [files, setFiles] = useState<File[]>([]);
  const [scanning, setScanning] = useState(false);
  const [stats, setStats] = useState<any>(null);
  const [queue, setQueue] = useState<any[]>([]);
  const navigate = useNavigate();

  const fetchStats = useCallback(async () => {
    try {
      const token = localStorage.getItem('token');
      const { data } = await axios.get('/api/analytics/dashboard', {
        headers: { Authorization: `Bearer ${token}` }
      });
      setStats(data);
    } catch (err) {
      console.error('Failed to fetch stats');
    }
  }, []);

  const fetchQueue = useCallback(async () => {
    try {
      const token = localStorage.getItem('token');
      const { data } = await axios.get('/api/scan/queue', {
        headers: { Authorization: `Bearer ${token}` }
      });
      if (Array.isArray(data)) {
        setQueue(data);
      } else {
        setQueue([]);
      }
    } catch (err) {
      console.error('Failed to fetch queue');
      setQueue([]);
    }
  }, []);

  useEffect(() => {
    fetchStats();
    fetchQueue();
    const interval = setInterval(fetchQueue, 5000);
    return () => clearInterval(interval);
  }, [fetchStats, fetchQueue]);

  const handleUpload = async (e: React.FormEvent) => {
    e.preventDefault();
    if (files.length === 0) return;

    setScanning(true);
    const formData = new FormData();
    files.forEach(f => formData.append('files', f));

    try {
      const token = localStorage.getItem('token');
      if (files.length === 1) {
        const singleFormData = new FormData();
        singleFormData.append('file', files[0]);
        const { data } = await axios.post('/api/scan', singleFormData, {
          headers: { 
            Authorization: `Bearer ${token}`,
            'Content-Type': 'multipart/form-data'
          }
        });
        navigate(`/scan/${data.id}`, { state: { scanData: data } });
      } else {
        await axios.post('/api/scan/batch', formData, {
          headers: { 
            Authorization: `Bearer ${token}`,
            'Content-Type': 'multipart/form-data'
          }
        });
        setFiles([]);
        fetchQueue();
      }
    } catch (err) {
      alert('Upload failed. Please try again.');
    } finally {
      setScanning(false);
    }
  };

  const doughnutData = {
    labels: ['Safe', 'Suspicious', 'Malware', 'High Risk'],
    datasets: [{
      data: stats?.stats ? [stats.stats.safe, stats.stats.suspicious, stats.stats.malware, stats.stats.high_risk] : [0, 0, 0, 0],
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
              className={`border-2 border-dashed border-[#141414]/20 p-12 text-center hover:border-[#141414] transition-colors cursor-pointer relative ${files.length > 0 ? 'bg-green-50' : ''}`}
              onDragOver={(e) => e.preventDefault()}
              onDrop={(e) => {
                e.preventDefault();
                if (e.dataTransfer.files) setFiles(Array.from(e.dataTransfer.files));
              }}
            >
              <input 
                type="file" 
                multiple
                onChange={(e) => e.target.files && setFiles(Array.from(e.target.files))}
                className="absolute inset-0 opacity-0 cursor-pointer"
              />
              <Search className="w-12 h-12 mx-auto mb-4 opacity-20" />
              {files.length > 0 ? (
                <div>
                  <p className="font-bold text-lg">{files.length} FILES_SELECTED</p>
                  <p className="font-mono text-xs opacity-50">
                    {files.map(f => f.name).join(', ').slice(0, 50)}...
                  </p>
                </div>
              ) : (
                <>
                  <p className="font-bold text-lg">DROP_FILES_OR_CLICK_TO_BROWSE</p>
                  <p className="font-mono text-xs opacity-50 mt-2">MAX_SIZE: 50MB | BATCH_LIMIT: 10_FILES</p>
                </>
              )}
            </div>

            <button 
              type="submit"
              disabled={files.length === 0 || scanning}
              className="w-full bg-[#141414] text-[#E4E3E0] py-4 font-bold flex items-center justify-center gap-2 hover:opacity-90 disabled:opacity-50 transition-opacity"
            >
              {scanning ? (
                <>
                  <Activity className="w-5 h-5 animate-spin" />
                  INITIATING_BATCH_PROCESS...
                </>
              ) : (
                <>
                  <ShieldCheck className="w-5 h-5" />
                  {files.length > 1 ? `SCAN_${files.length}_FILES` : 'INITIATE_SCAN'}
                </>
              )}
            </button>
          </form>

          {queue.length > 0 && (
            <div className="mt-12 border-t border-[#141414]/10 pt-8">
              <h3 className="font-mono font-bold text-sm mb-4 uppercase opacity-50">Active_Scan_Queue</h3>
              <div className="space-y-3">
                {queue.map((job) => (
                  <div key={job.id} className="flex items-center justify-between p-3 border border-[#141414]/5 bg-gray-50">
                    <div className="flex items-center gap-3">
                      <FileText className="w-4 h-4 opacity-40" />
                      <div>
                        <p className="text-xs font-bold truncate w-40">{job.filename}</p>
                        <p className="text-[10px] font-mono opacity-50 uppercase">{job.status}</p>
                      </div>
                    </div>
                    <div className="flex items-center gap-4">
                      <div className="w-24 h-1.5 bg-gray-200 rounded-full overflow-hidden">
                        <div 
                          className={`h-full transition-all duration-500 ${job.status === 'failed' ? 'bg-red-600' : 'bg-blue-600'}`}
                          style={{ width: `${job.progress}%` }}
                        />
                      </div>
                      <span className="font-mono text-[10px] font-bold">{job.progress}%</span>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}
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
          { label: 'SCAN_ENGINE', value: 'v4.0.0', color: 'text-[#141414]' },
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
