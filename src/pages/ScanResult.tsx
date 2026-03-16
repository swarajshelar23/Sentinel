import { useLocation, useParams, Link } from 'react-router-dom';
import React, { useState, useEffect, useRef } from 'react';
import axios from 'axios';
import { motion, AnimatePresence } from 'motion/react';
import { 
  ShieldAlert, ShieldCheck, FileText, Hash, Activity, ExternalLink, 
  ChevronLeft, PieChart as ChartIcon, MessageSquare, Send, Sparkles, 
  Terminal, Box, Cpu, Info, AlertCircle
} from 'lucide-react';
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer } from 'recharts';
import { GoogleGenAI } from "@google/genai";

export default function ScanResult() {
  const { id } = useParams();
  const location = useLocation();
  const scanData = location.state?.scanData;
  
  const [explanation, setExplanation] = useState<string | null>(null);
  const [explaining, setExplaining] = useState(false);
  const [chatMessage, setChatMessage] = useState('');
  const [chatHistory, setChatHistory] = useState<{ role: string, text: string }[]>([]);
  const [chatting, setChatting] = useState(false);
  const chatEndRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (chatEndRef.current) {
      chatEndRef.current.scrollIntoView({ behavior: 'smooth' });
    }
  }, [chatHistory]);

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

  const handleExplain = async () => {
    setExplaining(true);
    
    // Check if API key is available
    const apiKey = import.meta.env.VITE_GEMINI_API_KEY;
    if (!apiKey || apiKey.includes('YOUR_')) {
      setExplanation("⚠️ AI Explanation is not configured.\n\nTo enable AI-powered explanations, set your GEMINI_API_KEY in the .env.local file:\n\nVITE_GEMINI_API_KEY=your_api_key_here\n\nGet a free API key at: https://aistudio.google.com/apikey");
      setExplaining(false);
      return;
    }
    
    try {
      const ai = new GoogleGenAI({ apiKey });
      const prompt = `
        As a cybersecurity expert, explain the following malware scan result to a user.
        
        File: ${features.filename}
        Size: ${features.filesize} bytes
        Entropy: ${features.entropy}
        Classification: ${report.classification}
        Threat Score: ${report.score}/100
        
        Indicators Found:
        ${features.indicators?.join('\n') || 'None'}
        
        YARA Matches:
        ${features.yara_matches.join('\n') || 'None'}
        
        Details:
        ${report.details?.join('\n') || 'N/A'}
        
        Please provide:
        1. A summary of why the file was classified this way.
        2. An explanation of the specific indicators found.
        3. Suggested security actions for the user.
        
        Keep the tone professional and technical but accessible.
      `;

      const response = await ai.models.generateContent({
        model: "gemini-3-flash-preview",
        contents: prompt,
      });
      setExplanation(response.text || "Unable to generate explanation.");
    } catch (err) {
      console.error('AI Explanation failed:', err);
      setExplanation("⚠️ AI service error. Please check:\n1. Your GEMINI_API_KEY is valid\n2. Your internet connection\n3. API quota not exceeded\n\nYou can still review the technical details below.");
    } finally {
      setExplaining(false);
    }
  };

  const handleChat = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!chatMessage.trim() || chatting) return;

    // Check if API key is available
    const apiKey = import.meta.env.VITE_GEMINI_API_KEY;
    if (!apiKey || apiKey.includes('YOUR_')) {
      setChatHistory(prev => [...prev, { 
        role: 'assistant', 
        text: "⚠️ Chat is not configured.\n\nTo enable the AI chat assistant, add your GEMINI_API_KEY to .env.local:\n\nVITE_GEMINI_API_KEY=your_api_key_here\n\nGet a free API key at: https://aistudio.google.com/apikey" 
      }]);
      return;
    }

    const userMsg = chatMessage;
    setChatMessage('');
    setChatHistory(prev => [...prev, { role: 'user', text: userMsg }]);
    setChatting(true);

    try {
      const ai = new GoogleGenAI({ apiKey });
      const systemInstruction = `
        You are the Sentinel AI Assistant. You help users understand malware scan reports.
        You have access to the following scan data:
        File: ${features.filename}
        Score: ${report.score}
        Classification: ${report.classification}
        Indicators: ${features.indicators?.join(', ')}
        
        Answer user questions accurately based on this data. If you don't know something, say so.
      `;

      const response = await ai.models.generateContent({
        model: "gemini-3-flash-preview",
        contents: [
          { text: systemInstruction },
          ...chatHistory.map(h => ({ text: `${h.role === 'user' ? 'User' : 'Assistant'}: ${h.text}` })),
          { text: `User: ${userMsg}` }
        ],
      });
      setChatHistory(prev => [...prev, { role: 'assistant', text: response.text || "I'm sorry, I couldn't process that request." }]);
    } catch (err) {
      console.error('AI Chat failed:', err);
      setChatHistory(prev => [...prev, { role: 'assistant', text: '⚠️ API Error: Please check your API key and try again.' }]);
    } finally {
      setChatting(false);
    }
  };

  return (
    <div className="max-w-6xl mx-auto space-y-8 pb-20">
      <Link to="/dashboard" className="inline-flex items-center gap-2 font-mono text-xs hover:underline">
        <ChevronLeft className="w-4 h-4" /> BACK_TO_DASHBOARD
      </Link>

      <div className="grid md:grid-cols-12 gap-8">
        {/* Left Column: Classification & Score */}
        <motion.div 
          initial={{ opacity: 0, x: -20 }}
          animate={{ opacity: 1, x: 0 }}
          className={`md:col-span-4 border-4 p-8 flex flex-col items-center justify-center text-center h-fit sticky top-24 ${
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
          
          {features.malware_family && (
            <div className="mb-4 px-3 py-1 bg-red-900 text-white font-mono text-[10px] font-bold uppercase">
              FAMILY: {features.malware_family}
            </div>
          )}

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

        {/* Right Column: Details & Advanced Analysis */}
        <div className="md:col-span-8 space-y-8">
          <motion.div 
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            className="border border-[#141414] p-8 bg-white"
          >
            <div className="flex items-center justify-between mb-6 border-b border-[#141414]/10 pb-4">
              <div className="flex items-center gap-2">
                <FileText className="w-6 h-6" />
                <h3 className="font-mono font-bold text-xl uppercase">File_Intelligence_Report</h3>
              </div>
              <button 
                onClick={handleExplain}
                disabled={explaining}
                className="flex items-center gap-2 bg-[#141414] text-[#E4E3E0] px-4 py-2 text-xs font-bold hover:opacity-90 disabled:opacity-50 transition-opacity"
              >
                {explaining ? <Activity className="w-3 h-3 animate-spin" /> : <Sparkles className="w-3 h-3" />}
                AI_EXPLAIN_REPORT
              </button>
            </div>

            <AnimatePresence>
              {explanation && (
                <motion.div 
                  initial={{ opacity: 0, height: 0 }}
                  animate={{ opacity: 1, height: 'auto' }}
                  exit={{ opacity: 0, height: 0 }}
                  className="mb-8 p-6 bg-blue-50 border-l-4 border-blue-600 font-sans text-sm leading-relaxed whitespace-pre-wrap"
                >
                  <div className="flex items-center gap-2 mb-2 font-mono text-[10px] font-bold text-blue-800 uppercase">
                    <Sparkles className="w-3 h-3" /> AI_GENERATED_EXPLANATION
                  </div>
                  {explanation}
                </motion.div>
              )}
            </AnimatePresence>

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
                  <p className="font-bold">SENTINEL_AI_v4.0</p>
                </div>
                {features.packer && (
                  <div>
                    <p className="font-mono text-[10px] uppercase opacity-50">Packer_Detected</p>
                    <p className="font-bold text-red-600">{features.packer}</p>
                  </div>
                )}
              </div>
            </div>

            {/* Suspicious Indicators */}
            {features.indicators && features.indicators.length > 0 && (
              <div className="mb-8 space-y-3">
                <h4 className="font-mono font-bold text-xs uppercase flex items-center gap-2">
                  <AlertCircle className="w-4 h-4 text-red-600" /> SUSPICIOUS_BEHAVIOR_INDICATORS
                </h4>
                <div className="grid grid-cols-1 gap-2">
                  {features.indicators.map((ind: string, i: number) => (
                    <div key={i} className="bg-red-50 border border-red-100 p-2 text-[10px] font-mono font-bold text-red-800 flex items-center gap-2">
                      <div className="w-1.5 h-1.5 bg-red-600 rounded-full" />
                      {ind}
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Advanced Analysis Tabs */}
            <div className="space-y-6">
              <div className="flex items-center gap-4 border-b border-[#141414]/10">
                <button className="pb-2 border-b-2 border-[#141414] font-mono text-[10px] font-bold uppercase">Static_Analysis</button>
                <button className="pb-2 opacity-30 font-mono text-[10px] font-bold uppercase cursor-not-allowed">Dynamic_Behavior</button>
                <button className="pb-2 opacity-30 font-mono text-[10px] font-bold uppercase cursor-not-allowed">Network_Traffic</button>
              </div>

              <div className="grid md:grid-cols-2 gap-6">
                <div className="space-y-4">
                  <h5 className="font-mono text-[10px] font-bold uppercase opacity-50 flex items-center gap-1">
                    <Terminal className="w-3 h-3" /> Extracted_Strings
                  </h5>
                  <div className="bg-gray-900 text-green-500 p-4 font-mono text-[10px] h-48 overflow-y-auto rounded border border-[#141414]">
                    {features.strings?.map((s: string, i: number) => (
                      <div key={i} className="truncate hover:bg-green-500/10 cursor-default">{s}</div>
                    )) || 'NO_STRINGS_EXTRACTED'}
                  </div>
                </div>
                <div className="space-y-4">
                  <h5 className="font-mono text-[10px] font-bold uppercase opacity-50 flex items-center gap-1">
                    <Box className="w-3 h-3" /> File_Header_Analysis
                  </h5>
                  <div className="border border-[#141414]/10 p-4 space-y-3 bg-gray-50 h-48 overflow-y-auto">
                    {features.headers ? Object.entries(features.headers).map(([k, v]) => (
                      <div key={k} className="flex justify-between items-center border-b border-[#141414]/5 pb-1">
                        <span className="font-mono text-[10px] opacity-50 uppercase">{k}</span>
                        <span className="font-mono text-[10px] font-bold">{String(v)}</span>
                      </div>
                    )) : 'NO_HEADER_DATA'}
                  </div>
                </div>
              </div>
            </div>
          </motion.div>

          {/* AI Chat Assistant */}
          <motion.div 
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.2 }}
            className="border border-[#141414] bg-white flex flex-col h-[500px]"
          >
            <div className="p-4 border-b border-[#141414] bg-[#141414] text-[#E4E3E0] flex items-center justify-between">
              <div className="flex items-center gap-2">
                <MessageSquare className="w-4 h-4" />
                <h4 className="font-mono font-bold text-xs uppercase">SENTINEL_AI_CHAT_ASSISTANT</h4>
              </div>
              <div className="flex items-center gap-1">
                <div className="w-2 h-2 bg-green-500 rounded-full animate-pulse" />
                <span className="font-mono text-[8px] opacity-70 uppercase">Online</span>
              </div>
            </div>

            <div className="flex-1 overflow-y-auto p-6 space-y-4 font-sans text-sm">
              <div className="bg-gray-100 p-3 rounded-lg max-w-[80%] self-start">
                <p className="font-bold text-[10px] font-mono mb-1 uppercase opacity-50">Sentinel_AI</p>
                I am ready to analyze this report. You can ask me about the detected threats, suspicious indicators, or suggested actions.
              </div>
              
              {chatHistory.map((msg, i) => (
                <div key={i} className={`flex flex-col ${msg.role === 'user' ? 'items-end' : 'items-start'}`}>
                  <div className={`${msg.role === 'user' ? 'bg-[#141414] text-[#E4E3E0]' : 'bg-gray-100'} p-3 rounded-lg max-w-[80%]`}>
                    <p className="font-bold text-[10px] font-mono mb-1 uppercase opacity-50">
                      {msg.role === 'user' ? 'You' : 'Sentinel_AI'}
                    </p>
                    <div className="whitespace-pre-wrap">{msg.text}</div>
                  </div>
                </div>
              ))}
              
              {chatting && (
                <div className="flex items-center gap-2 text-xs font-mono opacity-50">
                  <Activity className="w-3 h-3 animate-spin" /> SENTINEL_IS_THINKING...
                </div>
              )}
              <div ref={chatEndRef} />
            </div>

            <form onSubmit={handleChat} className="p-4 border-t border-[#141414] flex gap-2">
              <input 
                type="text" 
                value={chatMessage}
                onChange={(e) => setChatMessage(e.target.value)}
                placeholder="ASK_ABOUT_THIS_SCAN..."
                className="flex-1 border border-[#141414] p-2 font-mono text-xs focus:outline-none"
              />
              <button 
                type="submit"
                disabled={!chatMessage.trim() || chatting}
                className="bg-[#141414] text-[#E4E3E0] p-2 hover:opacity-90 disabled:opacity-50 transition-opacity"
              >
                <Send className="w-4 h-4" />
              </button>
            </form>
          </motion.div>
        </div>
      </div>
    </div>
  );
}
