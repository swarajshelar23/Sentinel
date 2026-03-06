import { useLocation, useParams, Link } from 'react-router-dom';
import { motion } from 'motion/react';
import { ShieldAlert, ShieldCheck, FileText, Hash, Activity, ExternalLink, ChevronLeft, PieChart as ChartIcon } from 'lucide-react';
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer } from 'recharts';

export default function ScanResult() {
  const { id } = useParams();
  const location = useLocation();
  const scanData = location.state?.scanData;

  if (!scanData) return (
    <div className="text-center py-20">
      <p className="font-mono mb-4">ERROR: SCAN_DATA_NOT_FOUND</p>
      <Link to="/dashboard" className="underline font-bold">RETURN_TO_BASE</Link>
    </div>
  );

  const { features, report } = scanData;
  const isMalicious = report.score >= 40;

  const contributions = report.contributions || { entropy: 0, yara: 0, virusTotal: 0, ai: 0 };

  const chartData = [
    {
      name: 'Score Contribution',
      Entropy: Math.round(contributions.entropy),
      YARA: Math.round(contributions.yara),
      VirusTotal: Math.round(contributions.virusTotal),
      AI: Math.round(contributions.ai),
    }
  ];

  return (
    <div className="max-w-5xl mx-auto space-y-8">
      <Link to="/dashboard" className="inline-flex items-center gap-2 font-mono text-xs hover:underline">
        <ChevronLeft className="w-4 h-4" /> BACK_TO_DASHBOARD
      </Link>

      <div className="grid md:grid-cols-3 gap-8">
        <motion.div 
          initial={{ opacity: 0, x: -20 }}
          animate={{ opacity: 1, x: 0 }}
          className={`md:col-span-1 border-4 p-8 flex flex-col items-center justify-center text-center ${
            report.classification === 'Safe' ? 'border-green-600 bg-green-50' : 
            report.classification === 'Suspicious' ? 'border-yellow-500 bg-yellow-50' : 
            'border-red-600 bg-red-50'
          }`}
        >
          {isMalicious ? <ShieldAlert className="w-20 h-20 text-red-600 mb-4" /> : <ShieldCheck className="w-20 h-20 text-green-600 mb-4" />}
          <h2 className="font-mono font-bold text-sm uppercase opacity-50 mb-1">Threat_Classification</h2>
          <p className={`text-4xl font-black mb-4 ${
            report.classification === 'Safe' ? 'text-green-600' : 
            report.classification === 'Suspicious' ? 'text-yellow-600' : 
            'text-red-600'
          }`}>
            {report.classification.toUpperCase()}
          </p>
          <div className="w-full bg-white/50 border border-[#141414]/10 p-4">
            <p className="font-mono text-xs mb-1 uppercase">Risk_Score</p>
            <p className="text-5xl font-black tracking-tighter">{report.score}/100</p>
          </div>

          <div className="w-full mt-6 space-y-2">
            <p className="font-mono text-[10px] uppercase opacity-50 text-left">Score_Composition</p>
            <div className="h-48 w-full">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart
                  layout="vertical"
                  data={chartData}
                  margin={{ top: 0, right: 0, left: -40, bottom: 0 }}
                >
                  <XAxis type="number" domain={[0, 100]} hide />
                  <YAxis type="category" dataKey="name" hide />
                  <Tooltip 
                    contentStyle={{ backgroundColor: '#141414', border: 'none', color: '#E4E3E0', fontFamily: 'monospace', fontSize: '10px' }}
                    itemStyle={{ color: '#E4E3E0' }}
                  />
                  <Bar dataKey="Entropy" stackId="a" fill="#3b82f6" />
                  <Bar dataKey="YARA" stackId="a" fill="#ef4444" />
                  <Bar dataKey="VirusTotal" stackId="a" fill="#f59e0b" />
                  <Bar dataKey="AI" stackId="a" fill="#8b5cf6" />
                </BarChart>
              </ResponsiveContainer>
            </div>
            <div className="grid grid-cols-2 gap-1">
              <div className="flex items-center gap-1 font-mono text-[8px] uppercase"><div className="w-2 h-2 bg-[#3b82f6]" /> Entropy</div>
              <div className="flex items-center gap-1 font-mono text-[8px] uppercase"><div className="w-2 h-2 bg-[#ef4444]" /> YARA</div>
              <div className="flex items-center gap-1 font-mono text-[8px] uppercase"><div className="w-2 h-2 bg-[#f59e0b]" /> VirusTotal</div>
              <div className="flex items-center gap-1 font-mono text-[8px] uppercase"><div className="w-2 h-2 bg-[#8b5cf6]" /> AI_Model</div>
            </div>
          </div>
        </motion.div>

        <motion.div 
          initial={{ opacity: 0, x: 20 }}
          animate={{ opacity: 1, x: 0 }}
          className="md:col-span-2 border border-[#141414] p-8 bg-white"
        >
          <div className="flex items-center gap-2 mb-6 border-b border-[#141414]/10 pb-4">
            <FileText className="w-6 h-6" />
            <h3 className="font-mono font-bold text-xl uppercase">File_Intelligence_Report</h3>
          </div>

          <div className="grid grid-cols-2 gap-6 mb-8">
            <div className="space-y-4">
              <div>
                <p className="font-mono text-[10px] uppercase opacity-50">Filename</p>
                <p className="font-bold break-all">{features.filename}</p>
              </div>
              <div>
                <p className="font-mono text-[10px] uppercase opacity-50">Filesize</p>
                <p className="font-bold">{(features.filesize / 1024).toFixed(2)} KB</p>
              </div>
              <div>
                <p className="font-mono text-[10px] uppercase opacity-50">Entropy_Score</p>
                <p className="font-bold flex items-center gap-2">
                  {features.entropy.toFixed(4)}
                  <span className={`text-[10px] px-1.5 py-0.5 border ${features.entropy > 7 ? 'border-red-600 text-red-600' : 'border-green-600 text-green-600'}`}>
                    {features.entropy > 7 ? 'HIGH' : 'NORMAL'}
                  </span>
                </p>
              </div>
            </div>
            <div className="space-y-4">
              <div>
                <p className="font-mono text-[10px] uppercase opacity-50">SHA256_Hash</p>
                <p className="font-mono text-[10px] break-all bg-gray-50 p-2 border border-[#141414]/5">{features.hash_sha256}</p>
              </div>
              <div>
                <p className="font-mono text-[10px] uppercase opacity-50">Detection_Engine</p>
                <p className="font-bold">SENTINEL_AI_v3.0</p>
              </div>
            </div>
          </div>

          {features.ai_probability !== undefined && (
            <div className="mb-8 p-4 border border-[#141414] bg-gray-50">
              <div className="flex justify-between items-center mb-2">
                <h4 className="font-mono font-bold text-xs uppercase">AI_Malware_Probability</h4>
                <span className={`font-mono text-xs font-bold ${features.ai_probability > 0.5 ? 'text-red-600' : 'text-green-600'}`}>
                  {features.ai_prediction?.toUpperCase()}
                </span>
              </div>
              <div className="w-full h-4 bg-gray-200 rounded-full overflow-hidden">
                <div 
                  className={`h-full transition-all duration-1000 ${features.ai_probability > 0.7 ? 'bg-red-700' : features.ai_probability > 0.4 ? 'bg-yellow-500' : 'bg-green-600'}`}
                  style={{ width: `${features.ai_probability * 100}%` }}
                />
              </div>
              <p className="font-mono text-[10px] mt-1 text-right opacity-50">CONFIDENCE_SCORE: {(features.ai_probability * 100).toFixed(2)}%</p>
            </div>
          )}

          <div className="space-y-4">
            <h4 className="font-mono font-bold text-xs uppercase border-l-4 border-[#141414] pl-2">Analysis_Findings</h4>
            <ul className="space-y-2">
              {report.details.map((detail: string, i: number) => (
                <li key={i} className="flex items-start gap-2 text-sm font-medium">
                  <Activity className="w-4 h-4 mt-0.5 text-[#141414]/40" />
                  {detail}
                </li>
              ))}
              {report.details.length === 0 && <li className="text-sm opacity-50 italic">No suspicious indicators found.</li>}
            </ul>
          </div>
        </motion.div>
      </div>

      <div className="grid md:grid-cols-2 gap-8">
        <div className="border border-[#141414] p-8 bg-white">
          <h4 className="font-mono font-bold text-xs uppercase mb-6 flex items-center gap-2">
            <Hash className="w-4 h-4" /> YARA_SIGNATURE_MATCHES
          </h4>
          {features.yara_matches.length > 0 ? (
            <div className="space-y-3">
              {features.yara_matches.map((match: string, i: number) => (
                <div key={i} className="bg-red-50 border border-red-200 p-3 flex justify-between items-center">
                  <span className="font-mono font-bold text-red-700">{match}</span>
                  <span className="text-[10px] bg-red-700 text-white px-2 py-1">CRITICAL</span>
                </div>
              ))}
            </div>
          ) : (
            <div className="text-center py-8 border border-dashed border-[#141414]/10">
              <p className="font-mono text-xs opacity-30 uppercase">No_Signatures_Matched</p>
            </div>
          )}
        </div>

        <div className="border border-[#141414] p-8 bg-white">
          <h4 className="font-mono font-bold text-xs uppercase mb-6 flex items-center gap-2">
            <ExternalLink className="w-4 h-4" /> EXTERNAL_THREAT_FEEDS
          </h4>
          <div className="space-y-4">
            <div className="flex justify-between items-center bg-gray-50 p-4 border border-[#141414]/5">
              <div>
                <p className="font-bold text-sm">VirusTotal Reputation</p>
                <p className="font-mono text-[10px] opacity-50">Real-time hash lookup</p>
              </div>
              <span className="text-xs font-bold px-2 py-1 border border-[#141414]">
                {scanData.vtResults ? 'DATA_AVAILABLE' : 'NO_MATCH_FOUND'}
              </span>
            </div>
            <div className="flex justify-between items-center bg-gray-50 p-4 border border-[#141414]/5">
              <div>
                <p className="font-bold text-sm">MalwareBazaar</p>
                <p className="font-mono text-[10px] opacity-50">Community sample database</p>
              </div>
              <span className="text-xs font-bold px-2 py-1 border border-[#141414] opacity-30">
                PENDING_QUERY
              </span>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
