import { useState, useEffect } from 'react';
import axios from 'axios';
import { motion } from 'motion/react';
import { Search, FileText, Calendar, ShieldAlert, ShieldCheck, ChevronRight } from 'lucide-react';
import { Link } from 'react-router-dom';

export default function History() {
  const [scans, setScans] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [searchTerm, setSearchTerm] = useState('');

  useEffect(() => {
    const fetchHistory = async () => {
      try {
        const token = localStorage.getItem('token');
        const { data } = await axios.get('/api/history', {
          headers: { Authorization: `Bearer ${token}` }
        });
        setScans(data);
      } catch (err) {
        console.error('Failed to fetch history');
      } finally {
        setLoading(false);
      }
    };
    fetchHistory();
  }, []);

  const filteredScans = scans.filter(scan => 
    scan.filename.toLowerCase().includes(searchTerm.toLowerCase()) ||
    scan.hash_sha256.toLowerCase().includes(searchTerm.toLowerCase())
  );

  if (loading) return <div className="font-mono text-center py-20">FETCHING_HISTORY_LOGS...</div>;

  return (
    <div className="max-w-6xl mx-auto space-y-8">
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <h1 className="text-4xl font-black tracking-tighter uppercase">Scan_History</h1>
          <p className="font-mono text-xs opacity-50">ARCHIVED_THREAT_REPORTS_DATABASE</p>
        </div>
        <div className="relative">
          <input 
            type="text" 
            placeholder="SEARCH_BY_NAME_OR_HASH..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="w-full md:w-80 border border-[#141414] p-3 pl-10 font-mono text-xs focus:outline-none"
          />
          <Search className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 opacity-50" />
        </div>
      </div>

      <div className="border border-[#141414] bg-white overflow-hidden">
        <div className="grid grid-cols-12 bg-[#141414] text-[#E4E3E0] p-4 font-mono text-[10px] uppercase tracking-widest">
          <div className="col-span-1">Status</div>
          <div className="col-span-4">Filename / Hash</div>
          <div className="col-span-2">Date</div>
          <div className="col-span-2">Risk_Score</div>
          <div className="col-span-2">Classification</div>
          <div className="col-span-1"></div>
        </div>

        <div className="divide-y divide-[#141414]/10">
          {filteredScans.map((scan, i) => (
            <motion.div 
              key={scan.id}
              initial={{ opacity: 0, y: 10 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: i * 0.05 }}
              className="grid grid-cols-12 p-4 items-center hover:bg-gray-50 transition-colors group"
            >
              <div className="col-span-1">
                {scan.threat_score >= 50 ? <ShieldAlert className="w-5 h-5 text-red-600" /> : <ShieldCheck className="w-5 h-5 text-green-600" />}
              </div>
              <div className="col-span-4">
                <p className="font-bold text-sm truncate pr-4">{scan.filename}</p>
                <p className="font-mono text-[10px] opacity-40 truncate pr-4">{scan.hash_sha256}</p>
              </div>
              <div className="col-span-2 font-mono text-xs opacity-60">
                {new Date(scan.created_at).toLocaleDateString()}
              </div>
              <div className="col-span-2">
                <div className="w-24 h-2 bg-gray-100 rounded-full overflow-hidden">
                  <div 
                    className={`h-full ${scan.threat_score >= 80 ? 'bg-red-900' : scan.threat_score >= 50 ? 'bg-red-600' : scan.threat_score >= 20 ? 'bg-yellow-500' : 'bg-green-600'}`}
                    style={{ width: `${scan.threat_score}%` }}
                  />
                </div>
                <span className="font-mono text-[10px] font-bold mt-1 block">{scan.threat_score}/100</span>
              </div>
              <div className="col-span-2">
                <span className={`text-[10px] font-bold px-2 py-1 border ${
                  scan.classification === 'Safe' ? 'border-green-600 text-green-600' : 
                  scan.classification === 'Suspicious' ? 'border-yellow-600 text-yellow-600' : 
                  'border-red-600 text-red-600'
                }`}>
                  {scan.classification.toUpperCase()}
                </span>
              </div>
              <div className="col-span-1 text-right">
                <Link 
                  to={`/scan/${scan.id}`} 
                  state={{ 
                    scanData: { 
                      features: { 
                        ...JSON.parse(scan.metadata), 
                        filename: scan.filename, 
                        filesize: scan.filesize, 
                        hash_sha256: scan.hash_sha256, 
                        entropy: scan.entropy, 
                        yara_matches: JSON.parse(scan.yara_matches),
                        ai_probability: scan.ai_probability,
                        ai_prediction: scan.ai_prediction
                      }, 
                      report: { 
                        score: scan.threat_score, 
                        classification: scan.classification, 
                        details: [] 
                      }, 
                      vtResults: JSON.parse(scan.vt_results) 
                    } 
                  }}
                  className="inline-flex items-center justify-center w-8 h-8 border border-[#141414] hover:bg-[#141414] hover:text-[#E4E3E0] transition-all"
                >
                  <ChevronRight className="w-4 h-4" />
                </Link>
              </div>
            </motion.div>
          ))}
          {filteredScans.length === 0 && (
            <div className="p-20 text-center font-mono opacity-30">
              NO_RECORDS_FOUND_IN_DATABASE
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
