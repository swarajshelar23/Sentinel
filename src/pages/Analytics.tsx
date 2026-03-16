import { useState, useEffect } from 'react';
import axios from 'axios';
import { motion } from 'motion/react';
import { 
  BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer, 
  LineChart, Line, PieChart, Pie, Cell 
} from 'recharts';
import { Activity, Shield, FileText, Target, TrendingUp, Cpu } from 'lucide-react';

export default function Analytics() {
  const [data, setData] = useState<any>(null);
  const [accuracy, setAccuracy] = useState<any>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchData = async () => {
      try {
        const token = localStorage.getItem('token');
        const [dashRes, accRes] = await Promise.all([
          axios.get('/api/analytics/dashboard', { headers: { Authorization: `Bearer ${token}` } }),
          axios.get('/api/analytics/ai-accuracy', { headers: { Authorization: `Bearer ${token}` } })
        ]);
        setData(dashRes.data);
        setAccuracy(accRes.data);
      } catch (err) {
        console.error('Failed to fetch analytics');
      } finally {
        setLoading(false);
      }
    };
    fetchData();
  }, []);

  if (loading) return <div className="font-mono text-center py-20">FETCHING_ANALYTICS_DATA...</div>;
  if (!data || !accuracy) return <div className="font-mono text-center py-20 text-red-600 uppercase">Error_Fetching_Analytics_Data</div>;

  const COLORS = ['#10b981', '#f59e0b', '#ef4444', '#7f1d1d'];

  const pieData = [
    { name: 'Safe', value: data.stats?.safe || 0 },
    { name: 'Suspicious', value: data.stats?.suspicious || 0 },
    { name: 'Malware', value: data.stats?.malware || 0 },
    { name: 'High Risk', value: data.stats?.high_risk || 0 }
  ];

  return (
    <div className="max-w-7xl mx-auto space-y-8">
      <div>
        <h1 className="text-4xl font-black tracking-tighter uppercase">Threat_Intelligence_Analytics</h1>
        <p className="font-mono text-xs opacity-50">REAL-TIME_DETECTION_METRICS_&_TRENDS</p>
      </div>

      {/* Top Stats */}
      <div className="grid md:grid-cols-4 gap-4">
        {[
          { label: 'TOTAL_SCANS', value: data.stats?.total || 0, icon: FileText, color: 'text-blue-600' },
          { label: 'MALICIOUS_DETECTED', value: (data.stats?.malware || 0) + (data.stats?.high_risk || 0), icon: Shield, color: 'text-red-600' },
          { label: 'AI_ACCURACY', value: `${((accuracy?.f1_score || 0) * 100).toFixed(1)}%`, icon: Cpu, color: 'text-purple-600' },
          { label: 'THREAT_VELOCITY', value: '+12%', icon: TrendingUp, color: 'text-yellow-600' }
        ].map((stat, i) => (
          <motion.div 
            key={i}
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: i * 0.1 }}
            className="border border-[#141414] p-6 bg-white"
          >
            <div className="flex justify-between items-start mb-4">
              <stat.icon className={`w-5 h-5 ${stat.color}`} />
              <span className="font-mono text-[10px] opacity-30 uppercase">Live_Feed</span>
            </div>
            <p className="font-mono text-[10px] uppercase opacity-50 mb-1">{stat.label}</p>
            <p className={`text-2xl font-black ${stat.color}`}>{stat.value}</p>
          </motion.div>
        ))}
      </div>

      <div className="grid md:grid-cols-12 gap-8">
        {/* Detection Trends */}
        <motion.div 
          initial={{ opacity: 0, x: -20 }}
          animate={{ opacity: 1, x: 0 }}
          className="md:col-span-8 border border-[#141414] p-8 bg-white"
        >
          <h3 className="font-mono font-bold text-sm mb-8 uppercase flex items-center gap-2">
            <Activity className="w-4 h-4" /> Detection_Trends_30D
          </h3>
          <div className="h-80 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <LineChart data={data.trends.reverse()}>
                <CartesianGrid strokeDasharray="3 3" stroke="#f0f0f0" />
                <XAxis dataKey="date" fontSize={10} fontFamily="monospace" />
                <YAxis fontSize={10} fontFamily="monospace" />
                <Tooltip 
                  contentStyle={{ backgroundColor: '#141414', border: 'none', color: '#E4E3E0', fontFamily: 'monospace', fontSize: '10px' }}
                />
                <Legend iconType="rect" wrapperStyle={{ fontSize: '10px', fontFamily: 'monospace' }} />
                <Line type="monotone" dataKey="count" name="Total Scans" stroke="#141414" strokeWidth={2} dot={false} />
                <Line type="monotone" dataKey="malicious" name="Malicious" stroke="#ef4444" strokeWidth={2} dot={false} />
              </LineChart>
            </ResponsiveContainer>
          </div>
        </motion.div>

        {/* Classification Distribution */}
        <motion.div 
          initial={{ opacity: 0, x: 20 }}
          animate={{ opacity: 1, x: 0 }}
          className="md:col-span-4 border border-[#141414] p-8 bg-white"
        >
          <h3 className="font-mono font-bold text-sm mb-8 uppercase flex items-center gap-2">
            <Target className="w-4 h-4" /> Classification_Mix
          </h3>
          <div className="h-64 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie
                  data={pieData}
                  innerRadius={60}
                  outerRadius={80}
                  paddingAngle={5}
                  dataKey="value"
                >
                  {pieData.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                  ))}
                </Pie>
                <Tooltip 
                  contentStyle={{ backgroundColor: '#141414', border: 'none', color: '#E4E3E0', fontFamily: 'monospace', fontSize: '10px' }}
                />
              </PieChart>
            </ResponsiveContainer>
          </div>
          <div className="mt-8 space-y-2">
            {pieData.map((entry, i) => (
              <div key={i} className="flex justify-between items-center text-[10px] font-mono">
                <div className="flex items-center gap-2">
                  <div className="w-2 h-2" style={{ backgroundColor: COLORS[i] }} />
                  <span className="uppercase">{entry.name}</span>
                </div>
                <span className="font-bold">{data.stats?.total ? ((entry.value / data.stats.total) * 100).toFixed(1) : '0.0'}%</span>
              </div>
            ))}
          </div>
        </motion.div>
      </div>

      <div className="grid md:grid-cols-2 gap-8">
        {/* File Types */}
        <div className="border border-[#141414] p-8 bg-white">
          <h3 className="font-mono font-bold text-sm mb-8 uppercase">Common_File_Extensions</h3>
          <div className="h-64 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={data.fileTypes || []}>
                <CartesianGrid strokeDasharray="3 3" stroke="#f0f0f0" />
                <XAxis dataKey="extension" fontSize={10} fontFamily="monospace" />
                <YAxis fontSize={10} fontFamily="monospace" />
                <Tooltip 
                  contentStyle={{ backgroundColor: '#141414', border: 'none', color: '#E4E3E0', fontFamily: 'monospace', fontSize: '10px' }}
                />
                <Bar dataKey="count" fill="#141414" />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* AI Performance */}
        <div className="border border-[#141414] p-8 bg-white">
          <h3 className="font-mono font-bold text-sm mb-8 uppercase">AI_Model_Performance</h3>
          <div className="space-y-6">
            {[
              { label: 'Precision', value: accuracy?.precision || 0 },
              { label: 'Recall', value: accuracy?.recall || 0 },
              { label: 'F1 Score', value: accuracy?.f1_score || 0 }
            ].map((metric, i) => (
              <div key={i}>
                <div className="flex justify-between items-center mb-2 font-mono text-[10px] uppercase">
                  <span>{metric.label}</span>
                  <span className="font-bold">{(metric.value * 100).toFixed(1)}%</span>
                </div>
                <div className="w-full h-2 bg-gray-100 rounded-full overflow-hidden">
                  <div 
                    className="h-full bg-purple-600 transition-all duration-1000"
                    style={{ width: `${metric.value * 100}%` }}
                  />
                </div>
              </div>
            ))}
            <div className="pt-4 border-t border-[#141414]/10">
              <p className="font-mono text-[10px] opacity-50 uppercase">Training_Set_Size</p>
              <p className="font-bold">{(accuracy?.total_trained || 0).toLocaleString()} SAMPLES</p>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
