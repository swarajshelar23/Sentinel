import { useLocation, useParams, Link } from 'react-router-dom';
import { motion } from 'motion/react';
import { ShieldAlert, ShieldCheck, FileText, Hash, Activity, ExternalLink, ChevronLeft } from 'lucide-react';

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
  const isMalicious = report.score >= 50;

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
                <p className="font-bold">SENTINEL_STATIC_v1.0</p>
              </div>
            </div>
          </div>

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
